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

# -*- coding: utf-8 -*-
"""

import re

from core.exceptions import PackageNotValid, OsConfigNotValid
from core.log import logger

from glanceclient.v2.client import Client as GlanceClient
from heatclient.v1.client import Client as HeatClient
from keystoneclient.v3.client import Client as KeystoneClient
from neutronclient.v2_0.client import Client as NeutronClient
from keystoneauth1 import identity, session
from novaclient import client as nova_client

import config
import utils

_RC_MAP = {}


def set_rc(host_ip, tenant_id):
    """
    缓存rc表
    """
    _RC_MAP[f'{host_ip}-{tenant_id}'] = RCFile(utils.RC_FILE_DIR + '/' + tenant_id + '/' + host_ip)


def del_rc(host_ip, tenant_id):
    """
    删除rc表
    """
    if f'{host_ip}-{tenant_id}' in _RC_MAP:
        _RC_MAP.pop(f'{host_ip}-{tenant_id}')


def get_rc(host_ip, tenant_id):
    """
    获取rc表
    """
    if f'{host_ip}-{tenant_id}' not in _RC_MAP:
        set_rc(host_ip, tenant_id)
    return _RC_MAP[f'{host_ip}-{tenant_id}']


def get_session(host_ip, tenant_id):
    """
    创建Openstack session
    """
    rc_data = get_rc(host_ip, tenant_id)
    auth = identity.Password(
        user_domain_name=rc_data.user_domain_name,
        username=rc_data.username,
        password=rc_data.password,
        project_domain_name=rc_data.project_domain_name,
        project_name=rc_data.project_name,
        auth_url=rc_data.auth_url
    )
    return session.Session(auth=auth, verify=config.server_ca_verify)


def create_heat_client(host_ip, tenant_id):
    """
    创建heat客户端
    """
    rc_data = get_rc(host_ip, tenant_id)
    return HeatClient(session=get_session(host_ip, tenant_id), endpoint_override=rc_data.heat_url)


def create_nova_client(host_ip, tenant_id):
    """
    创建nova客户端
    """
    rc_data = get_rc(host_ip, tenant_id)
    return nova_client.Client('2',
                              session=get_session(host_ip, tenant_id),
                              endpoint_override=rc_data.nova_url)


def create_glance_client(host_ip, tenant_id):
    """
    创建glance客户端
    """
    rc_data = get_rc(host_ip, tenant_id)
    return GlanceClient(session=get_session(host_ip, tenant_id), endpoint_override=rc_data.glance_url)


def create_keystone_client(host_ip, tenant_id):
    """
    创建keystone客户端
    Args:
        host_ip:
        tenant_id:

    Returns:

    """
    return KeystoneClient(session=get_session(host_ip, tenant_id))


def create_neutron_client(host_ip, tenant_id):
    """

    Args:
        host_ip:
        tenant_id:

    Returns:

    """
    rc_data = get_rc(host_ip, tenant_id)
    return NeutronClient(session=get_session(host_ip, tenant_id), endpoint_override=rc_data.neutron_url)


def get_image_by_name_checksum(name, checksum, host_ip, tenant_id):
    """
    根据名称和校验和获取镜像
    Args:
        tenant_id: 租户id
        name: 名称
        checksum: 校验和
        host_ip:

    Returns: 镜像信息

    """
    glance = create_glance_client(host_ip, tenant_id)
    images = glance.images.list(filters={'name': name})
    for image in images:
        if image['checksum'] == checksum:
            return image
    raise RuntimeError(f'image {name} 不存在')


class RCFile:
    """
    rc文件解析类
    """
    _PATTERN = r'^export (.+)=(.+)$'

    user_domain_name = 'Default'
    project_domain_name = 'Default'
    username = None
    password = None
    project_name = None
    auth_url = None
    heat_url = None
    nova_url = None
    glance_url = None
    neutron_url = None

    def __init__(self, rc_path):
        try:
            with open(rc_path, 'r') as file:
                for line in file.readlines():
                    if line == '\n':
                        continue
                    match = re.match(self._PATTERN, line)
                    group1 = match.group(1)
                    group2 = match.group(2).replace('"', '')
                    if group1 == 'OS_AUTH_URL':
                        self.auth_url = group2
                    elif group1 == 'OS_USERNAME':
                        self.username = group2
                    elif group1 == 'OS_PASSWORD':
                        self.password = group2
                    elif group1 == 'OS_PROJECT_NAME':
                        self.project_name = group2
                    elif group1 == 'OS_PROJECT_DOMAIN_NAME':
                        self.project_domain_name = group2
                    elif group1 == 'OS_USER_DOMAIN_NAME':
                        self.user_domain_name = group2
                    elif group1 == 'HEAT_URL':
                        self.heat_url = group2
                    elif group1 == 'GLANCE_URL':
                        self.glance_url = group2
                    elif group1 == 'NOVA_URL':
                        self.nova_url = group2
                    elif group1 == 'CINDER_URL':
                        self.cinder_url = group2
                    elif group1 == 'NEUTRON_URL':
                        self.neutron_url = group2
        except Exception as exception:
            logger.error(exception, exc_info=True)
            raise OsConfigNotValid()

    def get_auth_url(self):
        """
        get auth url
        Returns:

        """
        return self.auth_url

    def get_heat_url(self):
        """
        get heat url
        Returns:

        """
        return self.heat_url


class HOTBase:
    """
    hot模板基础类型
    """

    def __init__(self, hot_type):
        self.type = hot_type

    def get_hot_type(self):
        """
        获取hot类型
        """
        return self.type

    def set_hot_type(self, hot_type):
        """
        设置hot类型
        """
        self.type = hot_type


def _change_function(properties):
    """
    把tosca input转换为hot param
    """
    if isinstance(properties, dict):
        if 'get_input' in properties:
            properties['get_param'] = properties.pop('get_input')
        if 'concat' in properties:
            properties['list_join'] = ['', properties.pop('concat')]
        for value in properties.values():
            _change_function(value)

    elif isinstance(properties, list):
        for item in properties:
            _change_function(item)


def _gen_runtime_script(inputs, user_data):
    """
    生产运行时脚本
    Args:
        inputs:
        user_data:

    Returns:

    """
    mec_runtime_script = ''
    if 'ak' in inputs and 'sk' in inputs:
        mec_runtime_script = 'echo \'ak=$ak$\\nsk=$sk$\\n\' >> /root/init.txt\n'
        if '$ak$' not in user_data['str_replace']['params']:
            user_data['str_replace']['params']['$ak$'] = {
                'get_input': 'ak'
            }
        if '$sk$' not in user_data['str_replace']['params']:
            user_data['str_replace']['params']['$sk$'] = {
                'get_input': 'sk'
            }
    return mec_runtime_script


class NovaServer(HOTBase):
    """
    hot nova类型
    """
    _TOSCA_TYPE = 'tosca.nodes.nfv.Vdu.Compute'

    def __init__(self, name, template):
        super().__init__('OS::Nova::Server')
        self.name = name
        self.template = template
        self.properties = {}
        if template['type'] != self._TOSCA_TYPE:
            raise PackageNotValid('错误的类型')

    def _check_availability_zone(self):
        """
        转换可用区
        """
        if 'nfvi_constraints' in self.template['properties']:
            self.properties['availability_zone'] = self.template['properties']['nfvi_constraints']

    def _check_user_data(self, inputs):
        """
        转换user data
        """
        user_data = {
            'str_replace': {
                'template': '',
                'params': {}
            }
        }
        if 'bootdata' in self.template['properties'] \
                and 'user_data' in self.template['properties']['bootdata']:
            if 'contents' in self.template['properties']['bootdata']['user_data']:
                user_data['str_replace']['template'] = \
                    self.template['properties']['bootdata']['user_data']['contents'] + '\n'
            if 'params' in self.template['properties']['bootdata']['user_data'] and \
                    self.template['properties']['bootdata']['user_data']['params'] is not None:
                params = {}
                for key, param in self.template['properties']['bootdata']['user_data']['params'] \
                        .items():
                    params['$' + key + '$'] = param
                user_data['str_replace']['params'] = params

        if user_data['str_replace']['template'] == '':
            user_data['str_replace']['template'] = '#!/bin/bash\n'

        mec_runtime_script = _gen_runtime_script(inputs, user_data)

        user_data['str_replace']['template'] = \
            user_data['str_replace']['template'] + mec_runtime_script

        self.properties['user_data'] = user_data
        if 'config_drive' in self.template['properties']['bootdata']:
            self.properties['config_drive'] = \
                self.template['properties']['bootdata']['config_drive']

    def _check_network(self, node_templates):
        """
        转换网络
        """
        for node_name, node_template in node_templates.items():
            if node_template['type'] == 'tosca.nodes.nfv.VduCp':
                for requirement in node_template['requirements']:
                    if 'virtual_binding' in requirement \
                            and requirement['virtual_binding'] == self.name:
                        self.properties['networks'].append({
                            'port': {
                                'get_resource': node_name
                            }
                        })

    def _check_data_disk(self):
        """
        转换数据盘
        """
        if 'requirements' in self.template:
            for requirement in self.template['requirements']:
                if 'virtual_storage' in requirement:
                    self.properties['block_device_mapping_v2'].append({
                        'volume_id': {
                            'get_resource': requirement['virtual_storage']
                        },
                        'delete_on_termination': True
                    })

    def _check_image(self, image_id_map):
        """
        转换镜像名称为id
        Args:
            image_id_map:

        Returns:

        """
        image_name = self.template['properties']['sw_image_data']['name']
        if image_name in image_id_map:
            self.properties['image'] = image_id_map[image_name]
        else:
            raise RuntimeError(f'image {image_name} not define in SwImageDesc.json')

    def set_properties(self, **kwargs):
        """
        转换属性
        Args:
            **kwargs:

        Returns:

        """
        # simple
        self.properties['name'] = self.template['properties']['name']
        self.properties['config_drive'] = True
        self.properties['user_data_format'] = 'RAW'
        self._check_availability_zone()

        # flavor
        hot_file = kwargs['hot_file']
        flavor_name = self.name + '_FLAVOR'
        flavor = Flavor(flavor_name, self.template)
        flavor.set_properties(hot_file=hot_file)
        self.properties['flavor'] = {
            'get_resource': flavor_name
        }

        # image
        image_id_map = kwargs['image_id_map']
        self._check_image(image_id_map)

        # user data
        inputs = kwargs['topology_template']['inputs']
        self._check_user_data(inputs)

        # network
        self.properties['networks'] = []
        node_templates = kwargs['topology_template']['node_templates']
        self._check_network(node_templates)

        # data disk
        self._check_data_disk()

        _change_function(self.properties)
        hot_file['resources'][self.name] = {
            'type': self.type,
            'properties': self.properties
        }
        hot_file['outputs'][self.name] = {
            'value': {
                'vmId': {
                    'get_resource': self.name
                },
                'vncUrl': {
                    'get_attr': [self.name, 'console_urls', 'novnc']
                },
                'networks': {
                    'get_attr': [self.name, 'addresses']
                }
            }
        }


class VirtualStorage(HOTBase):
    """
    hot volume类型
    """
    _TOSCA_TYPE = 'tosca.nodes.nfv.Vdu.VirtualBlockStorage'

    def __init__(self, name, template):
        super().__init__('OS::Cinder::Volume')
        self.name = name
        self.template = template
        self.properties = {}

    def set_properties(self, **kwargs):
        """
        转换属性
        Args:
            **kwargs:

        Returns:

        """
        hot_file = kwargs['hot_file']

        self._set_size()

        _change_function(self.properties)
        hot_file['resources'][self.name] = {
            'type': self.type,
            'properties': self.properties
        }

    def _set_size(self):
        """
        设置大小
        Returns:

        """
        size = self.template['properties']['virtual_block_storage_data']['size_of_storage']
        self.properties['size'] = size


class VirtualPort(HOTBase):
    """
    hot port类型
    """

    def __init__(self, name, template):
        super().__init__('OS::Neutron::Port')
        self.name = name
        self.template = template
        self.properties = {}

    def _set_fixed_ips(self):
        """
        设置ip
        Returns:

        """
        if 'attributes' in self.template and 'ipv4_address' in self.template['attributes']:
            self.properties['fixed_ips'] = [{
                'ip_address': self.template['attributes']['ipv4_address']
            }]

    def set_properties(self, **kwargs):
        """
        设置属性
        Args:
            **kwargs:
                topology_template:


        Returns:

        """
        node_templates = kwargs['topology_template']['node_templates']
        hot_file = kwargs['hot_file']
        network = None
        for requirement in self.template['requirements']:
            if 'virtual_link' in requirement:
                network = \
                    node_templates[requirement['virtual_link']][
                        'properties']['vl_profile']['network_name']
        if network is None:
            raise PackageNotValid('network未定义')
        self.properties['network'] = network
        if 'vnic_type' in self.template['properties']:
            self.properties['binding:vnic_type'] = self.template['properties']['vnic_type']
        if 'port_security_enabled' in self.template['properties']:
            self.properties['port_security_enabled'] = \
                self.template['properties']['port_security_enabled']

        self._set_fixed_ips()

        _change_function(self.properties)
        hot_file['resources'][self.name] = {
            'type': self.type,
            'properties': self.properties
        }


class Flavor(HOTBase):
    """
    flavor 类型
    """

    def __init__(self, name, template):
        super().__init__('OS::Nova::Flavor')
        self.name = name
        self.template = template
        self.properties = {}

    def set_properties(self, **kwargs):
        """
        设置属性
        Args:
            **kwargs:
                hot_file:

        Returns:

        """
        hot_file = kwargs['hot_file']
        cpu = self.template['capabilities'][
            'virtual_compute']['properties']['virtual_cpu']['num_virtual_cpu']
        memory = self.template['capabilities'][
            'virtual_compute']['properties']['virtual_memory']['virtual_mem_size']
        sys_disk = self.template['capabilities'][
            'virtual_compute']['properties']['virtual_local_storage']['size_of_storage']
        self.properties['vcpus'] = cpu
        self.properties['ram'] = memory
        self.properties['disk'] = sys_disk

        if 'flavor_extra_specs' in self.template['properties']['vdu_profile'] \
                and self.template['properties']['vdu_profile']['flavor_extra_specs'] is not None:
            flavor_extra_specs = self.template['properties']['vdu_profile']['flavor_extra_specs']
            self.properties['extra_specs'] = {}
            for key in flavor_extra_specs:
                if isinstance(flavor_extra_specs[key], bool):
                    self.properties['extra_specs'][key] = 'true' \
                        if flavor_extra_specs[key] else 'false'
                elif isinstance(flavor_extra_specs[key], (int, float)):
                    self.properties['extra_specs'][key] = str(flavor_extra_specs[key])
                else:
                    logger.info(flavor_extra_specs[key])
                    self.properties['extra_specs'][key] = flavor_extra_specs[key]

        _change_function(self.properties)
        hot_file['resources'][self.name] = {
            'type': self.type,
            'properties': self.properties
        }


def create_security_group_template():
    """
    创建安全组模版
    Returns:

    """
    return {
        'type': 'OS::Neutron::SecurityGroup',
        'properties': {
            'rules': [
                {'protocol': 'tcp', 'remote_mode': 'remote_group_id'},
                {'protocol': 'udp', 'remote_mode': 'remote_group_id'},
                {'protocol': 'icmp', 'remote_mode': 'remote_group_id'}
            ]
        }
    }


class SecurityGroup(HOTBase):
    """
    安全组
    """

    def __init__(self, name, template):
        super().__init__('OS::Neutron::SecurityGroup')
        self.name = name
        self.template = template
        self.properties = {}

    def set_properties(self, **kwargs):
        """
        设置属性
        Args:
            **kwargs:

        Returns:

        """
        hot_file = kwargs['hot_file']
        if self.name not in hot_file['resources']:
            hot_file['resources'][self.name] = create_security_group_template()
        for port in self.template['members']:
            if port in hot_file['resources']:
                if 'security_groups' in hot_file['resources'][port]['properties']:
                    hot_file['resources'][port]['properties']['security_groups'].append({
                        'get_resource': self.name
                    })
                else:
                    hot_file['resources'][port]['properties']['security_groups'] = [{
                        'get_resource': self.name
                    }]


class SecurityGroupRule(HOTBase):
    """
    安全组规则
    """

    def __init__(self, name, template):
        super().__init__('UNKNOWN::TYPE')
        self.name = name
        self.template = template
        self.properties = {}

    def set_properties(self, **kwargs):
        """
        设置属性
        Args:
            **kwargs:

        Returns:

        """
        hot_file = kwargs['hot_file']

        if 'protocol' in self.template['properties']:
            self.properties['protocol'] = self.template['properties']['protocol']
        if 'direction' in self.template['properties']:
            self.properties['direction'] = self.template['properties']['direction']
        if 'remote_ip_prefix' in self.template['properties']:
            self.properties['remote_ip_prefix'] = \
                self.template['properties']['remote_ip_prefix']

        _change_function(self.properties)

        for target in self.template['targets']:
            if target not in hot_file['resources']:
                hot_file['resources'][target] = create_security_group_template()
            hot_file['resources'][target]['properties']['rules'].append(self.properties)


TOSCA_TYPE_CLASS = {
    'tosca.nodes.nfv.Vdu.Compute': NovaServer,
    'tosca.nodes.nfv.VduCp': VirtualPort,
    'tosca.nodes.nfv.Vdu.VirtualBlockStorage': VirtualStorage,
}

TOSCA_GROUP_CLASS = {
    'tosca.groups.nfv.PortSecurityGroup': SecurityGroup
}

TOSCA_POLICY_CLASS = {
    'tosca.policies.nfv.SecurityGroupRule': SecurityGroupRule
}
