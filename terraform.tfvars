/* Node Settings */
openstack_nodes_ssh_root_password = "****"
// controller
controller_node_hostname = "controller"
controller_node_internal_ip_address = "172.29.0.105"
controller_node_internal_ip_address_prefix_length = "24"
controller_node_internal_interface = "eno1"
controller_node_external_ip_address = "192.168.110.240"
controller_node_external_ip_address_prefix_length = "24"
controller_node_external_interface = "eno2"
// compute
compute_node_hostname = "com-1"
compute_node_internal_ip_address = "172.29.0.101"
compute_node_internal_ip_address_prefix_length = "24"
compute_node_internal_interface = "eno1"
compute_node_external_ip_address = "192.168.110.101"
compute_node_external_ip_address_prefix_length = "24"
compute_node_external_interface = "eno2"

/* OpenStack Settings */
# openstack_keystone_admin_password = "openstack"
# openstack_octavia_ca_password = "openstack"
# openstack_octavia_client_ca_password = "openstack"
# openstack_octavia_keystone_password = "openstack"
# openstack_databases_password = "openstack"
openstack_vip_internal = "172.29.0.100"
openstack_vip_external = "192.168.110.100"
openstack_external_subnet_range = "192.168.110.0/24"
openstack_external_subnet_pool_start_ip_address = "192.168.110.211"
openstack_external_subnet_pool_end_ip_address = "192.168.110.239"
openstack_external_subnet_pool_gateway = "192.168.110.254"
openstack_internal_subnet_range = "10.0.0.0/24"
openstack_internal_subnet_gateway = "10.0.0.1"
# openstack_router_enable_snat = false
# openstack_create_cirros_test_image = true
# openstack_cirros_test_image_version = "0.6.1"

/* OpenStack NFS configuration */
// NFS server /etc/exports NFS options: (rw,nohide,sync,no_subtree_check,insecure,no_root_squash)
// Need permission for cinder UID, GID: 42407, 42400
openstack_cinder_volumes_nfs_target = "172.29.0.105:/Storage/openstack/cinder"
// Need permission for glance UID, GID: 42415, 42415
openstack_glance_images_nfs_target = "172.29.0.105:/Storage/openstack/images"
// Need permission for nova-compute UID, GID: 42436, 42436
openstack_nova_compute_instances_nfs_target = "172.29.0.105:/Storage/openstack/instances"
