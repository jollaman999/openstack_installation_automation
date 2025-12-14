# Terraform 기반 OpenStack 자동 설치 스크립트 이용 가이드

## 1. 요구 사항

- 필요 노드 3대 (Controller 노드, Compute 노드, Storage 노드)
- Controller 노드 요구 사항
    - CPU: 4Core 이상
    - RAM: 8GB 이상
    - Disk: 10GB 이상
    - NIC 2개
        - External: 외부 통신용 1개
        - Internal: 내부 통신용 1개
    - OS: Ubuntu 20.04 LTS
    - Kernel: 4.15+, IPv6 Enabled
    - Python 3.6.x~3.7.x
    - SSH Server Installed
- Compute 노드 요구 사항
    - CPU: 솔루션 설치를 위해 16Core 이상 권장, 가상화 활성화
    - RAM: 솔루션 설치를 위해 32GB 이상 권장
    - Disk:  10GB 이상
    - NIC 2개
        - External: 외부 통신용 1개
        - Internal: 내부 통신용 1개
    - OS: Ubuntu 20.04 LTS
    - Kernel: 4.15+, IPv6 Enable, KVM Enabled
    - Python 3.6.x~3.7.x
    - SSH Server Installed
- Storage 노드 요구 사항
    - NFS 서버 활성화
    - Disk: 1TB 이상 권장
    - NIC 1개
        - Internal: 내부 통신용 1개

## 2. 설치 후 사용 가능한 서비스

### 핵심 서비스
- **Keystone** - Identity 서비스
- **Glance** - Image 서비스
- **Nova** - Compute 서비스
- **Neutron** - Networking 서비스 (OVN 플러그인)
- **Cinder** - Block Storage 서비스 (NFS 백엔드)
- **Horizon** - Dashboard 서비스

### 추가 서비스
- **Octavia** - Load Balancing 서비스
- **Heat** - Orchestration 서비스
- **Manila** - Shared File System 서비스

## 3. 사전 필요 설정 사항

- Controller 노드
    - NIC
        - External
            - 외부 인터넷과 통신 가능하도록 IP, Gateway, 네임서버를 설정합니다.
            - Compute 노드와 같은 네트워크에 속하도록 구성합니다.
        - Internal
            - Compute 노드, Storage 노드와 통신 가능하도록 IP를 설정합니다.
    - SSH 서버 설치 및 root 계정 패스워드 로그인 활성화 (Compute 노드와 동일한 패스워드 설정)
- Compute  노드
    - NIC
        - External
            - 외부 인터넷과 통신 가능하도록 IP, Gateway, 네임서버를 설정합니다.
            - Controller 노드와 같은 네트워크에 속하도록 구성합니다.
        - Internal
            - Controller 노드, Storage 노드와 통신 가능하도록 IP를 설정합니다.
    - SSH 서버 설치 및 root 계정 패스워드 로그인 활성화 (Controller 노드와 동일한 패스워드 설정)
- Storage 노드
    - NIC
        - Internal
            - Controller 노드, Compute 노드와 통신 가능하도록 IP를 설정합니다.
    - NFS 서버 설치 및 Controller 노드와 Compute 노드의 External, Internal IP들 허용가능도록 /etc/exports 파일을 설정합니다.
    - /etc/exports 파일에 다음 3개의 폴더에 대해 exports 필요
        - 각 폴더의 exports 옵션 설정
            
            (rw,nohide,sync,no_subtree_check,insecure,no_root_squash)
            
        - cinder
            - 필요 권한 UID, GID: 42407, 42400
        - images
            - 필요 권한 UID, GID: 42415, 42415
        - instances
            - 필요 권한 UID, GID: 42436, 42436
        - 폴더 권한 예시
            
            ```bash
            # ls -aln
            total 20
            drwxr-xr-x  5     0     0 4096 Feb  2 11:00 .
            drwxr-xr-x 25     0     0 4096 Feb  2 10:59 ..
            drwxr-xr-x  2 42407 42400 4096 Feb  3 11:10 cinder
            drwxr-xr-x  2 42415 42415 4096 Feb  2 13:06 images
            drwxr-xr-x  5 42436 42436 4096 Feb  3 11:11 instances
            ```
            
        - /etc/exports 예시
            
            ```bash
            # Openstack
            /Storage/openstack/cinder 172.29.0.0/255.255.255.0(rw,nohide,sync,no_subtree_check,insecure,no_root_squash)
            /Storage/openstack/images 172.29.0.0/255.255.255.0(rw,nohide,sync,no_subtree_check,insecure,no_root_squash)
            /Storage/openstack/instances 172.29.0.0/255.255.255.0(rw,nohide,sync,no_subtree_check,insecure,no_root_squash)
            ```

## 4. 설치 옵션 변수 설정

terraform.tfvars 파일을 열어 설치에 필요한 변수들을 설정합니다.

```bash
/* Node Settings */
openstack_nodes_ssh_root_password = "****"
// controller
controller_node_hostname = "ct-01"
controller_node_internal_ip_address = "172.19.0.111"
controller_node_internal_ip_address_prefix_length = "24"
controller_node_internal_interface = "eno1"
controller_node_external_ip_address = "192.168.110.191"
controller_node_external_ip_address_prefix_length = "24"
controller_node_external_interface = "eno2"
// compute
compute_node_hostname = "cp-01"
compute_node_internal_ip_address = "172.19.0.112"
compute_node_internal_ip_address_prefix_length = "24"
compute_node_internal_interface = "eno1"
compute_node_external_ip_address = "192.168.110.192"
compute_node_external_ip_address_prefix_length = "24"
compute_node_external_interface = "eno2"

/* OpenStack Settings */
# openstack_keystone_admin_password = "openstack"
# openstack_octavia_ca_password = "openstack"
# openstack_octavia_client_ca_password = "openstack"
# openstack_octavia_keystone_password = "openstack"
# openstack_databases_password = "openstack"
openstack_vip_internal = "172.19.0.100"
openstack_vip_external = "192.168.110.190"
openstack_external_subnet_range = "192.168.110.0/24"
openstack_external_subnet_pool_start_ip_address = "192.168.110.180"
openstack_external_subnet_pool_end_ip_address = "192.168.110.189"
openstack_external_subnet_pool_gateway = "192.168.110.254"
openstack_internal_subnet_range = "10.0.0.0/24"
openstack_internal_subnet_gateway = "10.0.0.1"
# openstack_router_enable_snat = false
# openstack_create_cirros_test_image = true
# openstack_cirros_test_image_version = "0.6.1"

/* OpenStack NFS configuration */
// NFS server /etc/exports NFS options: (rw,nohide,sync,no_subtree_check,insecure,no_root_squash)
// Need permission for cinder: 42407
openstack_cinder_volumes_nfs_target = "172.29.0.10:/Storage/openstack/cinder"
// Need permission for glance: 42415
openstack_glance_images_nfs_target = "172.29.0.10:/Storage/openstack/images"
// Need permission for nova-compute: 42436
openstack_nova_compute_instances_nfs_target = "172.29.0.10:/Storage/openstack/instances"
```
            
- 공통
    - openstack_nodes_ssh_root_password
        
        OpenStack 노드별 SSH 접속시 사용될 비밀번호를 설정합니다.
        
- Controller 노드 관련 설정
    - controller_node_hostname
        
        Controller 노드의 호스트 명을 설정합니다.
        
        예시 : “ct-01”
        
    - controller_node_internal_ip_address
        
        Controller 노드의 내부 인터페이스에 사용할 IP 주소를 설정합니다.
        
        예시 : "172.19.0.111"
        
    - controller_node_internal_ip_address_prefix_length
        
        Controller 노드의 내부 인터페이스에 설정할 IP 주소의 Prefix 길이를 설정합니다.
        
        예시 : “24”
        
    - controller_node_internal_interface
        
        Controller 노드의 내부 인터페이스명을 설정합니다.
        
        예시 : “eno1”
        
    - controller_node_external_ip_address
        
        Controller 노드의 외부 인터페이스에 사용할  IP 주소를 설정합니다.
        
        예시 : "192.168.110.191"
        
    - controller_node_external_ip_address_prefix_length
        
        Controller 노드의 외부 인터페이스에 사용할 IP 주소의 Prefix 길이를 설정합니다.
        
        예시 : "24"
        
    - controller_node_external_interface
        
        Controller 노드의 외부 인터페이스명을 설정합니다.
        
        예시 : “eno2”
        
- Compute 노드 관련 설정
    - compute_node_hostname
        
        Compute 노드의 호스트 명을 설정합니다.
        
        예시 : "cp-01"
        
    - compute_node_internal_ip_address
        
        Compute 노드의 내부 인터페이스에 사용할 IP 주소를 설정합니다.
        
        예시 : "172.19.0.112"
        
    - compute_node_internal_ip_address_prefix_length
        
        Compute 노드의 내부 인터페이스에 사용할 IP 주소의 Prefix 길이를 설정합니다.
        
        예시 : "24"
        
    - compute_node_internal_interface
        
        Compute 노드의 내부 인터페이스명을 설정합니다.
        
        예시 : "eno1"
        
    - compute_node_external_ip_address
        
        Compute 노드의 외부 인터페이스에 사용할  IP 주소를 설정합니다.
        
        예시 : "192.168.110.192"
        
    - compute_node_external_ip_address_prefix_length
        
        Compute 노드의 외부 인터페이스에 사용할 IP 주소의 Prefix 길이를 설정합니다.
        
        예시 : "24"
        
    - compute_node_external_interface
        
        Compute 노드의 외부 인터페이스명을 설정합니다.
        
        예시 : "eno2"
        
- OpenStack
    - openstack_keystone_admin_password
        - admin 계정으로 로그인시 사용할 암호를 설정합니다.
        - 기본값 : "openstack"
    - openstack_octavia_ca_password
        - Octavia CA 인증서 생성시 사용할 암호를 설정합니다.
        - 기본값 : "openstack"
    - openstack_octavia_client_ca_password
        - Octavia Client 인증서 생성시 사용할 암호를 설정합니다.
        - 기본값 : "openstack"
    - openstack_octavia_keystone_password
        - octavia 사용자가 사용할 암호를 설정합니다.
        - 기본값 : "openstack"
    - openstack_databases_password
        - OpenStack에 사용되는 데이터베이스들에 사용할 암호를 설정합니다.
        - 기본값 : "openstack"
    - openstack_vip_internal
        - OpenStack의 내부 인터페이스 로드밸런싱에 사용할 VIP를 설정합니다.
        - 예시 : "172.19.0.100"
    - openstack_vip_external
        - OpenStack의 외부 인터페이스 로드밸런싱에 사용할 VIP를 설정합니다.
        - 예시 : "192.168.110.190"
    - openstack_external_subnet_range
        - OpenStack에서 외부 IP 할당시 사용할 서브넷 범위를 설정합니다.
        - 예시 : "192.168.110.0/24"
    - openstack_external_subnet_pool_start_ip_address
        - OpenStack에서 외부 IP 할당시 사용될 처음 시작 주소를 설정합니다.
        - 예시 : "192.168.110.180"
    - openstack_external_subnet_pool_end_ip_address
        - OpenStack에서 외부 IP 할당시 사용될 마지막 끝 주소를 설정합니다.
        - 예시 : "192.168.110.189"
    - openstack_external_subnet_pool_gateway
        - OpenStack에서 외부 IP 할당시 사용되는 서브넷에서 사용할 게이트웨이 주소를 설정합니다.
        - 예시 : "192.168.110.254"
    - openstack_interanl_subnet_range
        - OpenStack 내부적으로 인스턴스에 사용할 서브넷 범위를 설정합니다.
        - 예시 : "10.0.0.0/24"
    - openstack_internal_subnet_gateway
        - OpenStack 내부적으로 인스턴스에 사용할 서브넷에서 사용할 게이트웨이 주소를 설정합니다. openstack_interanl_subnet_range 범위에 속하는 IP중 하나를 지정하여 설정하면 됩니다.
        - 예시 : "10.0.0.1"
    - openstack_router_enable_snat
        - OpenStack 라우터에서 SNAT 기능을 사용할지 여부를 설정합니다. 활성화 된 경우 인스턴스는 openstack_interanl_subnet_range 서브넷 범위내에서 IP를 할당받고 외부로 나갈시 NAT를 통해 외부 주소로 변환되어 Floating IP를 할당하지 않고도 외부 통신이 가능합니다. 활성화 되어 있지 않은 경우 인스턴스가 외부로 통신하기 위해서는 Floating IP가 할당되어 있어야 합니다.
        - 사용가능한 값 : true 또는 false
        - 기본값 : false
    - openstack_create_cirros_test_image = true
        - OpenStack 설치가 완료되고 난 후 CirrOS 이미지를 구성합니다. 용량이 작은 이미지로 간단하게 인스턴스가 정상적으로 동작하는지 테스트하는 용도로 사용할 수 있습니다.
        - 사용가능한 값 : true 또는 false
        - 기본값 : true
    - openstack_cirros_test_image_version = "0.6.1"
        - CirrOS 이미지 구성시 사용할 버전을 설정합니다.
        - 버전 참고 : [https://github.com/cirros-dev/cirros/tags](https://github.com/cirros-dev/cirros/tags)
        - 기본값 : "0.6.1"
- OpenStack NFS 마운트 경로 설정
    
    NFS Server에서 /etc/exports 파일에 각 폴더의 옵션을 다음과 같이 설정합니다.
    
    (rw,nohide,sync,no_subtree_check,insecure,no_root_squash)
    
    - openstack_cinder_volumes_nfs_target
        - Cinder 모듈에서 Volume 저장시 사용될 NFS 타겟 경로를 설정합니다.
        - NFS 서버에서 해당 폴더의 UID, GID 권한은 42407로 설정되어 있어야 합니다.
        - 예시 : "172.29.0.10:/Storage/openstack/cinder"
    - openstack_glance_images_nfs_target
        - Glance 모듈에서 Image 저장시 사용될 NFS 타겟 경로를 설정합니다.
        - NFS 서버에서 해당 폴더의 UID, GID 권한은 42415로 설정되어 있어야 합니다.
        - 예시 : "172.29.0.10:/Storage/openstack/images"
    - openstack_nova_compute_instances_nfs_target
        - Nova Compute 모듈에서 인스턴스 저장시 사용될 NFS 타겟 경로를 설정합니다.
        - NFS 서버에서 해당 폴더의 UID, GID 권한은 42436으로 설정되어 있어야 합니다.
        - 예시 : "172.29.0.10:/Storage/openstack/instances"

## 5. 자동화 설치 스크립트 실행

Controller 노드에서 자동화 스크립트를 실행합니다.

```bash
cd openstack_install_automation/
./install_openstack

...(생략)...

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

...(생략)...

[*] Installation finished!
[*] Please reboot the system.
```

## 6. 로그 확인

설치 과정 중에 출력된 메세지들은 스크립트 실행 폴더에 `log.out` 이라는 파일로 기록됩니다.

```bash
vi log.out
```

## 7. Terraform State 파일 정리

Terraform 설치 스크립트를 실행하면서 저장된 State를 초기화 하기 위해서는 스크립트 실행 폴더에 있는 `clean_terraform_states.sh` 스크립트를 실행합니다.

```bash
./clean_terraform_states.sh
```
