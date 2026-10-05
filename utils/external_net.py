#!/usr/bin/env python3
# Keeps the node's external IP reachable while kolla-ansible puts the external interface into OVS.
#
#   prepare  : move the external IP onto Linux bridge brext0 (members: external interface, veth vext0)
#              so kolla can be given vext1 instead of the external interface itself.
#   cutover  : after deploy, put the external interface into br-ex and move the IP onto br-ex,
#              then remove brext0 and the veth pair.
#   restore  : go back to the state saved before prepare (pre-openstack) or before cutover (veth).
#
# Every change is guarded by a dead man timer: if the node does not confirm connectivity within
# ROLLBACK_SECONDS, systemd restores the saved state even when the calling SSH session is gone.

import argparse
import glob
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time

import yaml

NETPLAN_DIR = "/etc/netplan"
OWN_FILE = os.path.join(NETPLAN_DIR, "999-netplan_openstack.yaml")
SKIP_FILES = {OWN_FILE, os.path.join(NETPLAN_DIR, "999-octavia.yaml")}
STATE_DIR = "/var/lib/openstack-external-net"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
BACKUP_PRE = os.path.join(STATE_DIR, "netplan.pre-openstack")
BACKUP_VETH = os.path.join(STATE_DIR, "netplan.veth")
KEEPALIVED_CONF = "/etc/kolla/keepalived/keepalived.conf"
KEEPALIVED_BACKUP = os.path.join(STATE_DIR, "keepalived.conf.veth")
INSTALLED = "/usr/local/sbin/openstack-external-net"
TIMER_UNIT = "openstack-external-net-rollback"
ROLLBACK_SECONDS = 120
SECTIONS = ("ethernets", "bonds", "vlans", "bridges")
BRIDGE = "brext0"
VETH_HOST = "vext0"
VETH_OVS = "vext1"
OVS_BRIDGE = "br-ex"


def log(msg):
    print("[*] " + msg, flush=True)


def run(cmd, check=True):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if check and r.returncode != 0:
        raise RuntimeError("%s failed (%d): %s" % (" ".join(cmd), r.returncode, r.stdout.strip()))
    return r


def ovs(*args, check=True):
    return run(["podman", "exec", "openvswitch_vswitchd", "ovs-vsctl"] + list(args), check=check)


def link_exists(name):
    return os.path.exists("/sys/class/net/" + name)


def mac_of(name):
    with open("/sys/class/net/%s/address" % name) as f:
        return f.read().strip()


def load_netplan():
    files = {}
    for path in sorted(glob.glob(os.path.join(NETPLAN_DIR, "*.yaml"))):
        if path in SKIP_FILES:
            continue
        with open(path) as f:
            files[path] = yaml.safe_load(f) or {}
    return files


def write_yaml(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def find_iface(files, name):
    """Return (path, section, definition) of the first netplan definition of name."""
    for path, data in files.items():
        net = data.get("network") or {}
        for section in SECTIONS:
            if name in (net.get(section) or {}):
                return path, section, net[section][name]
    return None, None, None


def strip_l3(defn, cidr):
    """Remove the given address, the default route and DHCP from a netplan interface definition."""
    nameservers = defn.pop("nameservers", None)
    addrs = [a for a in defn.get("addresses", []) if str(a) != cidr]
    if addrs:
        defn["addresses"] = addrs
    else:
        defn.pop("addresses", None)
    defn.pop("gateway4", None)
    routes = [r for r in defn.get("routes", []) if str(r.get("to")) not in ("default", "0.0.0.0/0")]
    if routes:
        defn["routes"] = routes
    else:
        defn.pop("routes", None)
    defn["dhcp4"] = False
    return nameservers


def l3_block(cidr, gateway, nameservers):
    return {
        "addresses": [cidr],
        "routes": [{"to": "default", "via": gateway}],
        "nameservers": nameservers or {"addresses": ["1.1.1.1", "1.0.0.1"]},
    }


def save_dir(src, dst):
    if os.path.exists(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def restore_dir(src):
    for path in glob.glob(os.path.join(NETPLAN_DIR, "*.yaml")):
        if os.path.basename(path) not in os.listdir(src):
            os.remove(path)
    for name in os.listdir(src):
        shutil.copy2(os.path.join(src, name), os.path.join(NETPLAN_DIR, name))


def arm_timer(target):
    run(["systemctl", "stop", TIMER_UNIT + ".timer"], check=False)
    run(["systemctl", "reset-failed", TIMER_UNIT + ".service"], check=False)
    run(["systemd-run", "--unit=" + TIMER_UNIT, "--on-active=%d" % ROLLBACK_SECONDS,
         "--timer-property=AccuracySec=1s", INSTALLED, "restore", "--to", target])
    log("Rollback to %s armed (%ds)." % (target, ROLLBACK_SECONDS))


def disarm_timer():
    run(["systemctl", "stop", TIMER_UNIT + ".timer"], check=False)
    log("Rollback disarmed.")


def wait_for(desc, func, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if func():
            log(desc + ": ok")
            return True
        time.sleep(2)
    print("[!] " + desc + ": failed", flush=True)
    return False


def gateway_ok(dev, gateway):
    return run(["ping", "-c", "1", "-W", "2", "-I", dev, gateway], check=False).returncode == 0


def internet_ok():
    return run(["curl", "-sS", "-o", "/dev/null", "-m", "10", "https://opendev.org"], check=False).returncode == 0


def ip_on(dev, ip):
    return (" %s/" % ip) in run(["ip", "-4", "-o", "addr", "show", "dev", dev], check=False).stdout


def check_connectivity(dev, state, vip):
    ok = wait_for("Gateway %s via %s" % (state["gateway"], dev), lambda: gateway_ok(dev, state["gateway"]), 40)
    ok = ok and wait_for("Internet access", internet_ok, 30)
    if ok and vip:
        ok = wait_for("VIP %s on %s" % (vip, dev), lambda: ip_on(dev, vip), 30)
    return ok


def prepare(args):
    os.makedirs(STATE_DIR, exist_ok=True)
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            if json.load(f).get("stage") in ("veth", "br-ex"):
                log("External network already prepared, skipping.")
                return 0
    if not link_exists(args.ext_if):
        raise RuntimeError("external interface %s not found" % args.ext_if)
    ip = str(ipaddress.ip_interface(args.ext_cidr).ip)
    state = {"stage": "pre-openstack", "ext_if": args.ext_if, "cidr": args.ext_cidr, "ip": ip,
             "gateway": args.gateway, "mac": mac_of(args.ext_if)}
    save_dir(NETPLAN_DIR, BACKUP_PRE)

    files = load_netplan()
    own = {"network": {"version": 2, "renderer": "networkd"}}
    net = own["network"]

    if args.int_if:
        path, section, defn = find_iface(files, args.int_if)
        if defn is None:
            net.setdefault("ethernets", {})[args.int_if] = {"addresses": [args.int_cidr]}
        elif args.int_cidr not in [str(a) for a in defn.get("addresses", [])]:
            defn.setdefault("addresses", []).append(args.int_cidr)

    path, section, defn = find_iface(files, args.ext_if)
    if defn is None:
        net.setdefault("ethernets", {})[args.ext_if] = {"dhcp4": False}
        nameservers = None
    else:
        nameservers = strip_l3(defn, args.ext_cidr)
    state["nameservers"] = nameservers

    net["virtual-ethernets"] = {VETH_HOST: {"peer": VETH_OVS}, VETH_OVS: {"peer": VETH_HOST}}
    bridge = {"interfaces": [args.ext_if, VETH_HOST], "macaddress": state["mac"],
              "parameters": {"stp": False, "forward-delay": 0}}
    bridge.update(l3_block(args.ext_cidr, args.gateway, nameservers))
    net["bridges"] = {BRIDGE: bridge}

    for p, data in files.items():
        write_yaml(p, data)
    write_yaml(OWN_FILE, own)
    shutil.copy2(os.path.abspath(__file__), INSTALLED)
    os.chmod(INSTALLED, 0o755)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

    arm_timer("pre-openstack")
    run(["netplan", "apply"])
    if not check_connectivity(BRIDGE, state, None):
        disarm_timer()
        restore(argparse.Namespace(to="pre-openstack"))
        raise RuntimeError("no connectivity on %s, restored the original network" % BRIDGE)
    disarm_timer()
    state["stage"] = "veth"
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)
    log("External IP %s is on %s, kolla gets %s." % (args.ext_cidr, BRIDGE, VETH_OVS))
    return 0


def cutover(args):
    with open(STATE_FILE) as f:
        state = json.load(f)
    if state["stage"] == "br-ex":
        log("External interface already on %s, skipping." % OVS_BRIDGE)
        return 0
    if state["stage"] != "veth":
        raise RuntimeError("unexpected stage %s" % state["stage"])
    ext_if = state["ext_if"]
    save_dir(NETPLAN_DIR, BACKUP_VETH)
    if args.vip and os.path.exists(KEEPALIVED_CONF):
        shutil.copy2(KEEPALIVED_CONF, KEEPALIVED_BACKUP)

    with open(OWN_FILE) as f:
        own = yaml.safe_load(f)
    net = own["network"]
    net.pop("virtual-ethernets", None)
    net.pop("bridges", None)
    net.setdefault("ethernets", {})[OVS_BRIDGE] = l3_block(state["cidr"], state["gateway"], state["nameservers"])
    write_yaml(OWN_FILE, own)

    arm_timer("veth")
    ovs("--if-exists", "del-port", OVS_BRIDGE, VETH_OVS)
    run(["ip", "link", "set", ext_if, "nomaster"])
    run(["ip", "link", "del", BRIDGE], check=False)
    run(["ip", "link", "del", VETH_HOST], check=False)
    ovs("--may-exist", "add-port", OVS_BRIDGE, ext_if)
    ovs("set", "bridge", OVS_BRIDGE, "other-config:hwaddr=" + state["mac"])
    run(["ip", "link", "set", OVS_BRIDGE, "up"])
    run(["netplan", "apply"])
    if args.vip and os.path.exists(KEEPALIVED_CONF):
        with open(KEEPALIVED_CONF) as f:
            conf = f.read()
        with open(KEEPALIVED_CONF, "w") as f:
            f.write(conf.replace("%s dev %s" % (args.vip, BRIDGE), "%s dev %s" % (args.vip, OVS_BRIDGE)))
        run(["systemctl", "restart", "kolla-keepalived-container.service"])
    if not check_connectivity(OVS_BRIDGE, state, args.vip):
        disarm_timer()
        restore(argparse.Namespace(to="veth"))
        raise RuntimeError("no connectivity on %s, restored %s" % (OVS_BRIDGE, BRIDGE))
    disarm_timer()
    state["stage"] = "br-ex"
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)
    log("External IP %s is on %s with %s." % (state["cidr"], OVS_BRIDGE, ext_if))
    return 0


def restore(args):
    with open(STATE_FILE) as f:
        state = json.load(f)
    ext_if = state["ext_if"]
    print("[!] Restoring the %s network state." % args.to, flush=True)
    if args.to == "veth":
        ovs("--if-exists", "del-port", OVS_BRIDGE, ext_if, check=False)
        run(["ip", "-4", "addr", "flush", "dev", OVS_BRIDGE], check=False)
        restore_dir(BACKUP_VETH)
        run(["netplan", "apply"], check=False)
        ovs("--may-exist", "add-port", OVS_BRIDGE, VETH_OVS, check=False)
        if os.path.exists(KEEPALIVED_BACKUP):
            shutil.copy2(KEEPALIVED_BACKUP, KEEPALIVED_CONF)
            run(["systemctl", "restart", "kolla-keepalived-container.service"], check=False)
        state["stage"] = "veth"
    else:
        restore_dir(BACKUP_PRE)
        run(["ip", "link", "set", ext_if, "nomaster"], check=False)
        run(["ip", "link", "del", BRIDGE], check=False)
        run(["ip", "link", "del", VETH_HOST], check=False)
        run(["netplan", "apply"], check=False)
        state["stage"] = "pre-openstack"
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)
    return 0


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--ext-if", required=True)
    p.add_argument("--ext-cidr", required=True)
    p.add_argument("--gateway", required=True)
    p.add_argument("--int-if")
    p.add_argument("--int-cidr")
    c = sub.add_parser("cutover")
    c.add_argument("--vip")
    r = sub.add_parser("restore")
    r.add_argument("--to", choices=("pre-openstack", "veth"), required=True)
    args = parser.parse_args()
    try:
        return {"prepare": prepare, "cutover": cutover, "restore": restore}[args.cmd](args)
    except RuntimeError as e:
        print("[!] " + str(e), flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
