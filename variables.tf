/* Node Settings */
variable "openstack_nodes_ssh_root_password" {
  description = "노드 SSH 접속시 사용할 root 계정 비빌번호"
  type = string
  sensitive = true
}
// controller
variable "controller_node_hostname" {
  description = "Controller 노드 호스트명"
  default = "controller"
}
variable "controller_node_internal_ip_address" {
  description = "Controller 노드 내부 인터페이스 IP 주소"
}
variable "controller_node_internal_ip_address_prefix_length" {
  description = "Controller 노드 내부 인터페이스 IP 주소 서브넷 마스크 Prefix"
}
variable "controller_node_internal_interface" {
  description = "Controller 노드 내부 인터페이스명"
}
variable "controller_node_external_ip_address" {
  description = "Controller 노드 외부 인터페이스 IP 주소"
}
variable "controller_node_external_ip_address_prefix_length" {
  description = "Controller 노드 외부 인터페이스 IP 주소 서브넷 마스크 Prefix"
}
variable "controller_node_external_interface" {
  description = "Controller 노드 외부 인터페이스명"
}
// all-in-one
variable "all_in_one" {
  description = "Controller 노드 1대에 Compute 역할까지 모두 설치 (true 이면 compute_nodes 를 비워둬야 함)"
  type = bool
  default = true
}
// compute
variable "compute_nodes" {
  description = "Compute 노드 목록 (all_in_one = false 일 때만 설정)"
  type = list(object({
    hostname = string
    internal_ip_address = string
    internal_ip_address_prefix_length = string
    internal_interface = string
    external_ip_address = string
    external_ip_address_prefix_length = string
    external_interface = string
  }))
  default = []
  validation {
    condition = length(distinct([for n in var.compute_nodes : n.hostname])) == length(var.compute_nodes)
    error_message = "compute_nodes has duplicated hostname."
  }
  validation {
    condition = length(distinct([for n in var.compute_nodes : n.internal_ip_address])) == length(var.compute_nodes)
    error_message = "compute_nodes has duplicated internal_ip_address."
  }
}

/* OpenStack Settings */
variable "openstack_keystone_admin_password" {
  description = "OpenStack Keystone 관리자 비밀번호"
  default = "openstack"
  type = string
  sensitive = true
}
variable "openstack_octavia_ca_password" {
  description = "OpenStack Octavia CA 비밀번호"
  default = "openstack"
  type = string
  sensitive = true
}
variable "openstack_octavia_client_ca_password" {
  description = "OpenStack Octavia 클라이언트 CA 비밀번호"
  default = "openstack"
  type = string
  sensitive = true
}
variable "openstack_octavia_keystone_password" {
  description = "OpenStack Octavia Keystone 비밀번호"
  default = "openstack"
  type = string
  sensitive = true
}
variable "openstack_databases_password" {
  description = "OpenStack Octavia Keystone 비밀번호"
  default = "openstack"
  type = string
  sensitive = true
}
variable "openstack_vip_internal" {
  description = "OpenStack 내부 Virtual IP"
}
variable "openstack_vip_external" {
  description = "OpenStack 외부 Virtual IP"
}
variable "openstack_external_subnet_range" {
  description = "OpenStack 외부 서브넷 범위"
}
variable "openstack_external_subnet_pool_start_ip_address" {
  description = "OpenStack 외부 서브넷 풀 시작 IP 주소"
}
variable "openstack_external_subnet_pool_end_ip_address" {
  description = "OpenStack 외부 서브넷 풀 마지막 IP 주소"
}
variable "openstack_external_subnet_pool_gateway" {
  description = "OpenStack 외부 서브넷 풀 게이트웨이 IP 주소"
}
variable "openstack_internal_subnet_range" {
  description = "OpenStack 내부 서브넷 범위"
}

variable "openstack_create_cirros_test_image" {
  description = "OpenStack CirrOS 테스트 이미지 생성"
  type = bool
  default = true
}
variable "openstack_cirros_test_image_version" {
  description = "OpenStack CirrOS 테스트 이미지 버전"
  default = "0.6.1"
  type = string
}

# OpenStack NFS configuration
variable "openstack_cinder_volumes_nfs_target" {
  description = "OpenStack Cinder 볼륨 NFS 타켓"
}
variable "openstack_glance_images_nfs_target" {
  description = "OpenStack Glance 이미지 NFS 타켓"
}
variable "openstack_nova_compute_instances_nfs_target" {
  description = "OpenStack Nova Compute 인스턴스 NFS 타켓"
}

