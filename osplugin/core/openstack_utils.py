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

from heatclient.v1.client import Client as HeatClient
from glanceclient.v2.client import Client as GlanceClient
from keystoneauth1 import identity, session
from novaclient import client as nova_client

import config
import utils
from core.exceptions import PackageNotValid

_RC_MAP = {}


def set_rc(host_ip):
    """
    缓存rc表
    """
    _RC_MAP[host_ip] = RCFile(utils.RC_FILE_DIR + '/' + host_ip)


def del_rc(host_ip):
    """
    删除rc表
    """
    _RC_MAP.pop(host_ip)


def get_rc(host_ip):
    """
    获取rc表
    """
    if host_ip not in _RC_MAP:
        rc_file_dir = utils.RC_FILE_DIR + '/' + host_ip
        _RC_MAP[host_ip] = RCFile(rc_file_dir)
    return _RC_MAP[host_ip]


def get_auth(host_ip):
    """
    初始化auth
    """
    rc_data = get_rc(host_ip)
    return identity.Password(
        user_domain_name=rc_data.user_domain_name,
        username=rc_data.username,
        password=rc_data.password,
        project_domain_name=rc_data.project_domain_name,
        project_name=rc_data.project_name,
        auth_url=rc_data.auth_url
    )


def get_session(host_ip):
    """
    创建Openstack session
    """
    return session.Session(auth=get_auth(host_ip), verify=config.server_ca_verify)


def create_heat_client(host_ip):
    """
    创建heat客户端
    """
    rc_data = get_rc(host_ip)
    auth = identity.Password(
        user_domain_name=rc_data.user_domain_name,
        username=rc_data.username,
        password=rc_data.password,
        project_domain_name=rc_data.project_domain_name,
        project_name=rc_data.project_name,
        auth_url=rc_data.auth_url
    )
    sess = session.Session(auth=auth, verify=config.server_ca_verify)
    return HeatClient(session=sess, endpoint_override=rc_data.heat_url)


def create_nova_client(host_ip):
    """
    创建nova客户端
    """
    rc_data = get_rc(host_ip)
    return nova_client.Client('2',
                              session=get_session(host_ip),
                              endpoint_override=rc_data.nova_url)


_GLANCE_CLIENT_MAP = {}


def create_glance_client(host_ip):
    """
    创建glance客户端
    """
    if host_ip in _GLANCE_CLIENT_MAP:
        return _GLANCE_CLIENT_MAP[host_ip]
    rc_data = get_rc(host_ip)
    client = GlanceClient(session=get_session(host_ip), endpoint_override=rc_data.glance_url)
    _GLANCE_CLIENT_MAP[host_ip] = client
    return client


def clear_glance_client(host_ip):
    """
    删除glance客户端
    """
    if host_ip in _GLANCE_CLIENT_MAP:
        _GLANCE_CLIENT_MAP.pop(host_ip)


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

    def __init__(self, rc_path):
        with open(rc_path, 'r') as file:
            for line in file.readlines():
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


def _change_input_to_param(properties):
    """
    把tosca input转换为hot param
    """
    if isinstance(properties, dict):
        if 'get_input' in properties:
            properties['get_param'] = properties.pop('get_input')
        for key, value in properties.items():
            _change_input_to_param(value)

    elif isinstance(properties, list):
        for item in properties:
            _change_input_to_param(item)


class NovaServer(HOTBase):
    """
    hot nova类型
    """
    _TOSCA_TYPE = 'tosca.nodes.nfv.Vdu.Compute'

    def __init__(self, name, template, hot_file, topology_template):
        super().__init__('OS::Nova::Server')
        if template['type'] != self._TOSCA_TYPE:
            raise PackageNotValid('错误的类型')

        flavor_name = name + '_FLAVOR'
        Flavor(flavor_name, template, hot_file)
        # simple
        self.properties = {
            'name': template['properties']['name'],
            'flavor': {
                'get_resource': flavor_name
            },
            'config_drive': True,
            'networks': [],
            'user_data_format': 'RAW'
        }

        self.check_image(template)

        self.check_availability_zone(template)

        # user data
        self.check_user_data(template)

        # network
        self.check_network(name, topology_template['node_templates'])

        # data disk
        self.check_data_disk(template)

        _change_input_to_param(self.properties)
        hot_file['resources'][name] = {
            'type': self.type,
            'properties': self.properties
        }
        hot_file['outputs'][name] = {
            'value': {
                'vmId': {
                    'get_resource': name
                },
                'vncUrl': {
                    'get_attr': [name, 'console_urls', 'novnc']
                },
                'networks': {
                    'get_attr': [name, 'addresses']
                }
            }
        }

    def check_availability_zone(self, template):
        """
        转换可用区
        """
        if 'nfvi_constraints' in template['properties']:
            self.properties['availability_zone'] = template['properties']['nfvi_constraints']

    def check_user_data(self, template):
        """
        转换user data
        """
        user_data = {
            'str_replace': {
                'template': '',
                'params': {}
            }
        }
        if 'bootdata' in template['properties'] \
                and 'user_data' in template['properties']['bootdata']:
            if 'contents' in template['properties']['bootdata']['user_data']:
                user_data['str_replace']['template'] = \
                    template['properties']['bootdata']['user_data']['contents'] + '\n'
            if 'params' in template['properties']['bootdata']['user_data']:
                params = {}
                for key, param in template['properties']['bootdata']['user_data']['params']\
                        .items():
                    params['$' + key + '$'] = param
                user_data['str_replace']['params'] = params

        if '' == user_data['str_replace']['template']:
            user_data['str_replace']['template'] = '#!/bin/bash\n'

        mec_runtime_script = '\n'
        for vnic_name in _VNIC_NAME_IP_MAP.keys():
            default_route = 'no'
            if vnic_name == 'eth2':
                default_route = 'yes'
            ip = _VNIC_NAME_IP_MAP[vnic_name]['ip']
            mask = _VNIC_NAME_IP_MAP[vnic_name]['mask']

            vnic_file = f'etc/sysconfig/network-scripts/ifcfg-{vnic_name}'
            mec_runtime_script += f'rm -rf {vnic_file}\n'
            mec_runtime_script += f'echo "BOOTPROTO=static" >> {vnic_file}\n'
            mec_runtime_script += f'echo "DEVICE={vnic_name}" >> {vnic_file}\n'
            mec_runtime_script += f'echo "TYPE=Ethernet" >> {vnic_file}\n'
            mec_runtime_script += f'echo "USERCTL=no" >> {vnic_file}\n'
            mec_runtime_script += f'echo "DEFAULTROUTE={default_route}" >> {vnic_file}\n'
            mec_runtime_script += f'echo "IPV4_FAILURE_FATAL=no" >> {vnic_file}\n'
            mec_runtime_script += f'echo "MTU=1500" >> {vnic_file}\n'
            mec_runtime_script += f'echo "IPADDR=${ip}$" >> {vnic_file}\n'
            mec_runtime_script += f'echo "NETMASK=${mask}$" >> {vnic_file}\n'

        mec_runtime_script += 'echo "$mep_ip$/32 via $app_mp1_gw$" >> ' \
                              '/etc/sysconfig/network-scripts/route-eth0\n'
        mec_runtime_script += 'echo "$ue_ip_segment$ via $app_n6_gw$" >> ' \
                              '/etc/sysconfig/network-scripts/route-eth1\n'
        mec_runtime_script += 'echo "GATEWAY=$app_internet_gw$" >> ' \
                              '/etc/sysconfig/network-scripts/ifcfg-eth2\n'
        mec_runtime_script += 'systemctl restart network\n'

        user_data['str_replace']['template'] = \
            user_data['str_replace']['template'] + mec_runtime_script

        self.properties['user_data'] = user_data
        if 'config_drive' in template['properties']['bootdata']:
            self.properties['config_drive'] = template['properties']['bootdata']['config_drive']

    def check_network(self, name, node_templates):
        """
        转换网络
        """
        for node_name, node_template in node_templates.items():
            if node_template['type'] == 'tosca.nodes.nfv.VduCp':
                for requirement in node_template['requirements']:
                    if 'virtual_binding' in requirement and requirement['virtual_binding'] == name:
                        self.properties['networks'].append({
                            'port': {
                                'get_resource': node_name
                            }
                        })

    def check_data_disk(self, template):
        """
        转换数据盘
        """
        if 'requirements' in template:
            for requirement in template['requirements']:
                if 'virtual_storage' in requirement:
                    self.properties['block_device_mapping_v2'].append({
                        'volume_id': {
                            'get_resource': requirement['virtual_storage']
                        },
                        'delete_on_termination': True
                    })

    def check_image(self, template):
        self.properties['image'] = template['properties']['sw_image_data']['name']


class VirtualStorage(HOTBase):
    """
    hot volume类型
    """
    _TOSCA_TYPE = 'tosca.nodes.nfv.Vdu.VirtualBlockStorage'

    def __init__(self, name, template, hot_file):
        super().__init__('OS::Cinder::Volume')
        self.template = template

        size = template['properties']['virtual_block_storage_data']['size_of_storage']

        self.properties = {
            'size': size
        }
        _change_input_to_param(self.properties)
        hot_file['resources'][name] = {
            'type': self.type,
            'properties': self.properties
        }

    def get_type(self):
        """
        get type
        Returns:

        """
        return self.type

    def get_properties(self):
        """
        get properties
        Returns:

        """
        return self.properties


_VNIC_NAME_IP_MAP = {
    'eth0': {
        'ip': 'app_mp1_ip',
        'mask': 'app_mp1_mask',
        'gw': 'app_mp1_gw'
    },
    'eth1': {
        'ip': 'app_n6_ip',
        'mask': 'app_n6_mask',
        'gw': 'app_n6_gw'
    },
    'eth2': {
        'ip': 'app_internet_ip',
        'mask': 'app_internet_mask',
        'gw': 'app_internet_gw'
    }
}


class VirtualPort(HOTBase):
    """
    hot port类型
    """
    def __init__(self, name, template, hot_file, topology_template):
        super().__init__('OS::Neutron::Port')
        network = None
        for requirement in template['requirements']:
            if 'virtual_link' in requirement:
                network = \
                    topology_template['node_templates'][requirement['virtual_link']][
                        'properties']['vl_profile']['network_name']
        if network is None:
            raise PackageNotValid('network未定义')

        self.properties = {
            'network': network,
            'security_groups': [{
                'get_resource': 'APP_DEFAULT_GROUPS'
            }]
        }
        if 'vnic_name' in template['properties']\
                and template['properties']['vnic_name'] in _VNIC_NAME_IP_MAP \
                and _VNIC_NAME_IP_MAP[template['properties']['vnic_name']]['ip'] \
                in topology_template['inputs']:
            self.properties['fixed_ips'] = [{
                'ip_address': {
                    'get_param': _VNIC_NAME_IP_MAP[template['properties']['vnic_name']]
                }
            }]

        if 'vnic_type' in template['properties']:
            self.properties['binding:vnic_type'] = template['properties']['vnic_type']
        if 'port_security_enabled' in template['properties']:
            self.properties['port_security_enabled'] = \
                template['properties']['port_security_enabled']

        _change_input_to_param(self.properties)
        hot_file['resources'][name] = {
            'type': self.type,
            'properties': self.properties
        }

    def get_type(self):
        """
        get type
        Returns:

        """
        return self.type

    def get_properties(self):
        """
        get properties
        Returns:

        """
        return self.properties


class Flavor(HOTBase):
    """
    flavor 类型
    """
    def __init__(self, name, template, hot_file):
        super().__init__('OS::Nova::Flavor')
        cpu = template['capabilities'][
            'virtual_compute']['properties']['virtual_cpu']['num_virtual_cpu']
        memory = template['capabilities'][
            'virtual_compute']['properties']['virtual_memory']['virtual_mem_size']
        sys_disk = template['capabilities'][
            'virtual_compute']['properties']['virtual_local_storage']['size_of_storage']
        self.properties = {
            'vcpus': cpu,
            'ram': memory,
            'disk': sys_disk
        }
        if 'flavor_extra_specs' in template['properties']['vdu_profile']:
            self.properties['extra_specs'] = template['properties'][
                'vdu_profile']['flavor_extra_specs']
        hot_file['resources'][name] = {
            'type': self.type,
            'properties': self.properties
        }


class SecurityGroup(HOTBase):
    def __init__(self, name, template, hot_file):
        super().__init__('OS::Neutron::SecurityGroup')
        hot_file['resources'][name] = {
            'type': self.type,
            'properties': {
                'rules': template['properties']['rules']
            }
        }


class SecurityGroupDefaultRule(HOTBase):
    def __init__(self, name, template, hot_file):
        super().__init__('OS::Neutron::SecurityGroupRule')
        hot_file['resources'][name] = {
            'type': self.type,
            'properties': {
                'protocol': template['properties']['protocol'],
                'security_group': {
                    'get_resource': template['properties']['father']
                },
                'remote_group': {
                    'get_resource': template['properties']['remote_group']
                }
            }
        }


TOSCA_TYPE_CLASS = {
    'tosca.nodes.nfv.Vdu.Compute': NovaServer,
    'tosca.nodes.nfv.VduCp': VirtualPort,
    'tosca.nodes.nfv.Vdu.VirtualBlockStorage': VirtualStorage,
}
