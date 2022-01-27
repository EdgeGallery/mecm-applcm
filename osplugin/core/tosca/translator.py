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
import copy
import logging

logger = logging.getLogger()


def translate(app_description):
    """
    翻译tosca为hot
    Args:
        app_description: tosca模板

    Returns: hot

    """
    hot = {
        'heat_template_version': '2016-10-14',
        'description': 'Generated By OsPlugin',
        'parameters': {},
        'resources': {},
        'outputs': {}
    }
    topology_template = app_description['topology_template']

    # 翻译参数声明
    if 'inputs' in app_description:
        hot['parameters'] = translate_inputs(topology_template['inputs'])

    # 翻译节点声明
    node_templates = topology_template['node_templates']
    for name, node_template in node_templates.items():
        resource_translator = NODE_TEMPLATE_MAPPER[node_template['type']]
        hot['resources'][name] = resource_translator(node_template, app_d=app_description)

    # 翻译组声明
    groups = topology_template['groups']
    for name, group in groups.items():
        group_translator = GROUP_MAPPER[group['type']]
        hot['resources'][name] = group_translator(group, app_d=app_description)

    # 翻译策略声明
    policies = topology_template['policies']
    for policy_obj in policies:
        name = policy_obj.keys()[0]
        policy = policy_obj[name]
        policy_translator = POLICY_MAPPER[policy['type']]
        hot['resources'][name] = policy_translator(policy, app_d=app_description)

    # 翻译函数
    for resource in hot['resources'].values():
        translate_function(resource['properties'])

    return hot


def translate_inputs(inputs):
    """
    把 inputs 翻译为 parameters
    hot不支持text、password类型参数，翻译为string
    Args:
        inputs: tosca参数模版

    Returns: parameters

    """
    parameters = copy.deepcopy(inputs)
    for key in parameters.keys():
        if parameters[key]['type'] == 'text' or parameters[key]['type'] == 'password':
            parameters[key]['type'] = 'string'
    return parameters


def translate_vdu_compute(node_template, **kwargs):
    resource = {
        'type': 'OS::Nova::Server',
        'properties': {}
    }
    return resource


def translate_vdu_cp(node_template, **kwargs):
    resource = {
        'type': 'OS::Neutron::Port',
        'properties': {}
    }
    return resource


def translate_vl(node_template, **kwargs):
    """
    网络不通过heat创建，翻译为neutron network
    Args:
        node_template: 网络模板
        **kwargs: 其他

    Returns: neutron network

    """
    network = {

    }
    return network


def translate_vdu_compute_profile(compute_profile, **kwargs):
    resource = {
        'type': 'OS::Nova::Flavor',
        'properties': {}
    }
    return resource


def translate_virtual_storage(node_template, **kwargs):
    resource = {
        'type': 'OS::Cinder::Volume',
        'properties': {}
    }
    return resource


def translate_port_security_group(group, **kwargs):
    resource = {
        'type': 'OS::Neutron::SecurityGroup',
        'properties': {}
    }
    return resource


def translate_security_group_rule(policy, **kwargs):
    resource = {
        'type': 'OS::Neutron::SecurityGroupRule',
        'properties': {}
    }
    return resource


def translate_function(properties):
    """
    翻译函数名称和实现
    目前支持的函数
    get_input: 翻译为 get_param ，参数列表不变
    concat: 翻译为 list_join ，参数列表变更为 ['', 原参数]
    其他函数有需求可实现
    Args:
        properties: 可能包含函数的obj对象

    Returns:

    """
    if isinstance(properties, dict):
        if 'get_input' in properties:
            properties['get_param'] = properties.pop('get_input')
        if 'concat' in properties:
            properties['list_join'] = ['', properties.pop('concat')]
        for value in properties.values():
            translate_function(value)

    elif isinstance(properties, list):
        for item in properties:
            translate_function(item)


def translate_unknown(unknown, **kwargs):
    """
    跳过翻译不支持的类型
    Args:
        unknown: 类型数据
        **kwargs: 其他

    Returns:

    """
    logger.info('skip translate unknown type %s', unknown['type'])


NODE_TEMPLATE_MAPPER = {
    'tosca.nodes.nfv.VNF': translate_unknown,
    'tosca.nodes.nfv.Vdu.Compute': translate_vdu_compute,
    'tosca.nodes.nfv.Vdu.VirtualStorage': translate_virtual_storage,
    'tosca.nodes.nfv.VduCp': translate_vdu_cp,
    'tosca.nodes.nfv.Cp': translate_unknown,
    'tosca.nodes.nfv.VnfVirtualLink': translate_unknown
}

GROUP_MAPPER = {
    'tosca.groups.nfv.PlacementGroup': translate_unknown,
    'tosca.groups.nfv.PortSecurityGroup': translate_port_security_group
}

POLICY_MAPPER = {
    'tosca.policies.nfv.AffinityRule': translate_unknown,
    'tosca.policies.nfv.AntiAffinityRule': translate_unknown,
    'tosca.policies.nfv.SecurityGroupRule': translate_security_group_rule
}

ComputeMapper = {
    'properties': {
        'name': 'name',
        'nfvi_constraints': 'availability_zone',
        'bootdata': {
            'user_data': {
                'contents': 'user_data',
                'params': ''
            }
        }
    },
    'attributes': {},
    'requirements': {}
}

VduCpMapper = {
    'properties.vnic_type': {
        'os_set': 'binding:vnic_type'
    },
    'properties.port_security_enabled': {
        'os_set': 'port_security_enabled'
    },
    'attributes.ipv4_address': {
        'os_append': {
            'key': 'fixed_ips',
            'value': 'ip_address'
        }
    },
    'attributes.ipv6_address': {
        'os_append': {
            'key': 'fixed_ips',
            'value': 'ip_address'
        }
    },
    'attributes.mac': {
        'os_set': 'mac_address'
    },
    'requirements.%d.virtual_link': {
        'os_set': 'network'
    }
}

VirtualStorageMapper = {
    'properties.virtual_storage_data.size_of_storage': {
        'set': 'size'
    },
    'properties.virtual_storage_data.volume_type.volume_type_name': {
        'set': 'volume_type'
    },
    'properties.sw_image_data.name': {
        'set': 'image'
    },
    'properties.nfvi_constraints': {
        'set': 'availability_zone'
    }
}

VnfVirtualLinkMapper = {}
