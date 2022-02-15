"""
# Copyright 2021 21CN Corporation Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
# -*- coding: utf-8 -*-

from core.tosca.map_action import SetAction, FunctionAction, AppendAction, data_mapping


def mapping_virtual_compute(virtual_compute, **kwargs):
    """
    把 tosca.capabilities.nfv.VirtualCompute 映射为OS::Nova::Flavor
    Args:
        virtual_compute: tosca.capabilities.nfv.VirtualCompute对象
        **kwargs:

    Returns:

    """
    node_templates = kwargs['app_d']['topology_template']['node_templates']
    node_name = kwargs['node_name']
    compute_template_properties = node_templates[node_name]['properties']

    resource = {
        'type': 'OS::Nova::Flavor',
        'properties': {}
    }
    data_mapping(VirtualComputeMapper, virtual_compute, resource['properties'], **kwargs)

    if 'vdu_profile' in compute_template_properties:
        properties = mapping_vdu_profile(compute_template_properties['vdu_profile'], **kwargs)
        resource['properties'].update(properties)
    flavor_node_name = node_name + '_FLAVOR'
    kwargs['hot']['resources'][flavor_node_name] = resource
    return {
        'get_resource': flavor_node_name
    }


def mapping_vdu_profile(vdu_profile, **kwargs):
    """
    映射资源调度配置
    Args:
        vdu_profile:
        **kwargs:

    Returns:

    """
    if 'flavor_extra_specs' not in vdu_profile:
        return {}
    extra_specs = {}
    flavor_extra_specs = vdu_profile['flavor_extra_specs']
    for key in flavor_extra_specs:
        if isinstance(flavor_extra_specs[key], bool):
            extra_specs[key] = 'true' if flavor_extra_specs[key] else 'false'
        elif isinstance(flavor_extra_specs[key], (int, float)):
            extra_specs[key] = str(flavor_extra_specs[key])
        else:
            extra_specs[key] = flavor_extra_specs[key]
    return {
        'extra_specs': extra_specs
    }


def mapping_user_data(user_data, **kwargs):
    """
    映射用户初始化数据
    Args:
        user_data:

    Returns:

    """
    if user_data['contents'] == '':
        return None
    if len(user_data['params'].keys()) == 0:
        return user_data['contents']
    params = {}
    for key in user_data['params'].keys():
        params[f'${key}$'] = user_data['params'][key]
    return {
        'str_replace': {
            'params': params,
            'template': user_data['contents']
        }
    }


def mapping_sw_image_data(sw_image_data, **kwargs):
    """
    映射镜像
    Args:
        sw_image_data:
        **kwargs:

    Returns:

    """
    sw_image_map = kwargs['sw_image_map']
    if sw_image_data['name'] not in sw_image_map:
        return sw_image_data['name']

    return sw_image_map[sw_image_data['name']]['id']


def mapping_require_storage(requirement, **kwargs):
    """
    映射云盘绑定
    Args:
        requirement:
        **kwargs:

    Returns:

    """
    block_device_mapping_v2 = {
        'delete_on_termination': True,
        'volume_id': {
            'get_resource': requirement
        }
    }
    node_templates = kwargs['app_d']['topology_template']['node_templates']

    if requirement in node_templates:
        block_storage = node_templates[requirement]['properties']
        sw_image_map = kwargs['sw_image_map']

        if 'sw_image_data' in block_storage and \
                block_storage['sw_image_data']['name'] in sw_image_map and \
                sw_image_map[block_storage['sw_image_data']['name']]['format'] == 'iso':
            block_device_mapping_v2['boot_index'] = 1
            block_device_mapping_v2['device_type'] = 'cdrom'

    return block_device_mapping_v2


def mapping_virtual_link(requirement, **kwargs):
    """
    映射网络绑定
    Args:
        requirement:
        **kwargs:

    Returns:

    """
    node_templates = kwargs['app_d']['topology_template']['node_templates']

    if requirement in node_templates:
        virtual_link = node_templates[requirement]['properties']
        return virtual_link['vl_profile']['network_name']


def mapping_ip_address(address, **kwargs):
    """
    翻译 vdu connect point l3 address
    Args:
        address:
        **kwargs:

    Returns:

    """
    return {'ip_address': address}


def mapping_ip_allocation_pool(ip_allocation_pool, **kwargs):
    """
    翻译 layer3 protocol data ip allocation pool
    Args:
        ip_allocation_pool:
        **kwargs:

    Returns:

    """
    properties = {}
    data_mapping(IpAllocationPoolMapper, ip_allocation_pool, properties, **kwargs)
    return properties


def mapping_l3_protocol_data(l3_protocol_data, **kwargs):
    """
    翻译 layer3 protocol data
    Args:
        l3_protocol_data:
        **kwargs:

    Returns:

    """
    properties = {}
    data_mapping(VnfVirtualLinkL3Mapper, l3_protocol_data, properties, **kwargs)
    return properties


ComputeMapper = {
    'properties.name': SetAction('name'),
    'properties.nfvi_constraints': SetAction('availability_zone'),
    'properties.bootdata.user_data': FunctionAction('user_data', mapping_user_data),
    'properties.bootdata.config_drive': SetAction('config_drive'),
    'properties.sw_image_data': FunctionAction('image', mapping_sw_image_data),
    'requirements.%d.virtual_storage':
        AppendAction('block_device_mapping_v2', mapping_require_storage),
    'capabilities.virtual_compute': FunctionAction('flavor', mapping_virtual_compute)
}

VirtualComputeMapper = {
    'properties.virtual_cpu.num_virtual_cpu': SetAction('vcpus'),
    'properties.virtual_memory.virtual_mem_size': SetAction('ram'),
    'properties.virtual_local_storage.size_of_storage': SetAction('disk'),
}

VduCpMapper = {
    'properties.vnic_type': SetAction('binding:vnic_type'),
    'properties.port_security_enabled': SetAction('port_security_enabled'),
    'attributes.ipv4_address': AppendAction('fixed_ips', mapping_ip_address, '0.0.0.0'),
    'attributes.ipv6_address': AppendAction('fixed_ips', mapping_ip_address, '00::00'),
    'attributes.mac': SetAction('mac_address', '00:00:00:00:00:00'),
    'requirements.%d.virtual_link': FunctionAction('network', mapping_virtual_link),
}

VirtualStorageMapper = {
    'properties.virtual_storage_data.size_of_storage': SetAction('size'),
    'properties.virtual_storage_data.volume_type.volume_type_name': SetAction('volume_type'),
    'properties.sw_image_data': FunctionAction('image', mapping_sw_image_data),
    'properties.nfvi_constraints': SetAction('availability_zone')
}

IpAllocationPoolMapper = {
    'start_ip_address': SetAction('start'),
    'end_ip_address': SetAction('end')
}

VnfVirtualLinkL3Mapper = {
    'name': SetAction('name'),
    'ip_version': SetAction('ip_version'),
    'cidr': SetAction('cidr'),
    'ip_allocation_pools.%d': AppendAction('allocation_pools', mapping_ip_allocation_pool),
    'gateway_ip': SetAction('gateway_ip'),
    'dhcp_enabled': SetAction('enable_dhcp'),
    'ipv6_ra_mode': SetAction('ipv6_ra_mode'),
    'ipv6_address_mode': SetAction('ipv6_address_mode'),
    'host_routes': SetAction('host_routes'),
    'dns_name_servers': SetAction('dns_nameservers')
}

VnfVirtualLinkMapper = {
    'properties.vl_profile.network_name': SetAction('name'),
    'properties.vl_profile.network_type': SetAction('provider:network_type'),
    'properties.vl_profile.physical_network': SetAction('provider:physical_network'),
    'properties.vl_profile.provider_segmentation_id': SetAction('provider:segmentation_id'),
    'properties.vl_profile.router_external': SetAction('router:external'),
    'properties.vl_profile.vlan_transparent': SetAction('vlan_transparent'),
    'properties.vl_profile.l3_protocol_data.%d': AppendAction('subnets', mapping_l3_protocol_data)
}

SecurityGroupMapper = {
    'properties.description': SetAction('description'),
    'properties.name': SetAction('name'),
}

SecurityGroupRuleMapper = {
    'properties.description': SetAction('description'),
    'properties.direction': SetAction('direction'),
    'properties.ether_type': SetAction('ether_type'),
    'properties.protocol': SetAction('protocol'),
    'properties.port_range_min': SetAction('port_range_min'),
    'properties.port_range_max': SetAction('port_range_max'),
    'properties.remote_ip_prefix': SetAction('remote_ip_prefix')
}
