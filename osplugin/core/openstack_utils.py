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
import os
import re

from heatclient.v1.client import Client as HeatClient
from keystoneauth1 import identity, session
from novaclient import client as nova_client

import config
import utils
from core.custom_glance_client import CustomGlanceClient
from core.exceptions import PackageNotValid


_RC_MAP = {}


def _init_rc_map():
    rc_file_dir = utils.RC_FILE_DIR + '/'
    for rc in os.listdir(rc_file_dir):
        _RC_MAP[rc] = RCFile(rc_file_dir + rc)


def set_rc(host_ip):
    _RC_MAP[host_ip] = RCFile(utils.RC_FILE_DIR + '/' + host_ip)


def del_rc(host_ip):
    _RC_MAP.pop(host_ip)


def get_rc(host_ip):
    if host_ip in _RC_MAP:
        return _RC_MAP[host_ip]
    raise FileNotFoundError(utils.RC_FILE_DIR + '/' + host_ip)


def get_auth(host_ip):
    rc = get_rc(host_ip)
    return identity.Password(
        user_domain_name=rc.user_domain_name,
        username=rc.username,
        password=rc.password,
        project_domain_name=rc.project_domain_name,
        project_name=rc.project_name,
        auth_url=rc.auth_url
    )


def get_session(host_ip):
    return session.Session(auth=get_auth(host_ip), verify=config.server_ca_verify)


def create_heat_client(host_ip):
    rc = get_rc(host_ip)
    auth = identity.Password(
        user_domain_name=rc.user_domain_name,
        username=rc.username,
        password=rc.password,
        project_domain_name=rc.project_domain_name,
        project_name=rc.project_name,
        auth_url=rc.auth_url
    )
    sess = session.Session(auth=auth, verify=config.server_ca_verify)
    return HeatClient(session=sess, endpoint_override=rc.heat_url)


def create_nova_client(host_ip):
    rc = get_rc(host_ip)
    return nova_client.Client('2',
                              session=get_session(host_ip),
                              endpoint_override=rc.nova_url)


_GLANCE_CLIENT_MAP = {}


def create_glance_client(host_ip):
    if host_ip in _GLANCE_CLIENT_MAP:
        return _GLANCE_CLIENT_MAP[host_ip]
    rc = get_rc(host_ip)
    asession = get_session(host_ip)
    client = CustomGlanceClient(session=asession, endpoint_override=rc.glance_url)
    _GLANCE_CLIENT_MAP[host_ip] = client
    return client


def clear_glance_client(host_ip):
    if host_ip in _GLANCE_CLIENT_MAP:
        _GLANCE_CLIENT_MAP.pop(host_ip)


class RCFile(object):
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


class HOTBase(object):
    def __init__(self, hot_type):
        self.type = hot_type


def _get_flavor(template):
    cpu = str(template['capabilities']['virtual_compute']['properties']['virtual_cpu']['num_virtual_cpu'])
    memory = str(template['capabilities']['virtual_compute']['properties']['virtual_memory'][
                     'virtual_mem_size'])
    sys_disk = str(template['capabilities']['virtual_compute']['properties']['virtual_local_storage'][
                       'size_of_storage'])

    return cpu + 'c-' + memory + 'm-' + sys_disk + 'g'


def _change_input_to_param(properties):
    if isinstance(properties, dict):
        if 'get_input' in properties:
            properties['get_param'] = properties.pop('get_input')
        for key, value in properties.items():
            _change_input_to_param(value)

    elif isinstance(properties, list):
        for item in properties:
            _change_input_to_param(item)
    else:
        pass


class NovaServer(HOTBase):
    _TOSCA_TYPE = 'tosca.nodes.nfv.Vdu.Compute'

    def __init__(self, name, template, hot_file, node_templates):
        super().__init__('OS::Nova::Server')
        if template['type'] != self._TOSCA_TYPE:
            raise PackageNotValid('错误的类型')

        # simple
        self.properties = {
            'name': template['properties']['name'],
            'flavor': _get_flavor(template),
            'config_drive': True,
            'image': template['properties']['sw_image_data']['name'],
            'networks': [],
            'user_data_format': 'RAW'
        }

        if 'vdu_profile' in template['properties']:
            # TODO 亲和性配置
            if 'flavor_extra_specs' in template['properties']['vdu_profile']:
                pass

        if 'nfvi_constraints' in template['properties']:
            self.properties['availability_zone'] = template['properties']['nfvi_constraints']

        # user data
        if 'bootdata' in template['properties']:
            if 'user_data' in template['properties']['bootdata']:
                if 'params' in template['properties']['bootdata']['user_data']:
                    params = {}
                    for key, param in template['properties']['bootdata']['user_data']['params'].items():
                        params['$' + key + '$'] = param
                    user_data = {
                        'str_replace': {
                            'template': template['properties']['bootdata']['user_data']['contents'],
                            'params': params
                        }
                    }
                else:
                    user_data = template['properties']['bootdata']['user_data']['contents']
                self.properties['user_data'] = user_data
            if 'config_drive' in template['properties']['bootdata']:
                self.properties['config_drive'] = template['properties']['bootdata']['config_drive']

        # network
        for node_name, node_template in node_templates.items():
            if node_template['type'] == 'tosca.nodes.nfv.VduCp':
                for requirement in node_template['requirements']:
                    if 'virtual_binding' in requirement and requirement['virtual_binding'] == name:
                        self.properties['networks'].append({
                            'port': {
                                'get_resource': node_name
                            }
                        })

        """
        # sys disk
        self.properties['block_device_mapping_v2'].append({
            'volume_id': {
                'get_resource': 'VirtualLocalStorage1'
            },
            'delete_on_termination': True
        })
        sys_disk = template['capabilities']['virtual_compute']['properties']['virtual_local_storage'][
            'size_of_storage']
        image = template['properties']['sw_image_data']['name']
        LocalStorage(sys_disk, image, hot_file)
        """

        # data disk
        if 'requirements' in template:
            for requirement in template['requirements']:
                if 'virtual_storage' in requirement:
                    self.properties['block_device_mapping_v2'].append({
                        'volume_id': {
                            'get_resource': requirement['virtual_storage']
                        },
                        'delete_on_termination': True
                    })

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


"""
class LocalStorage(HOTBase):
    def __init__(self, size, image, hot_file):
        super().__init__('OS::Cinder::Volume')
        self.properties = {
            'image': image,
            'size': size
        }
        hot_file['resources']['VirtualLocalStorage1'] = {
            'type': self.type,
            'properties': self.properties
        }
"""


class VirtualStorage(HOTBase):
    _TOSCA_TYPE = 'tosca.nodes.nfv.Vdu.VirtualBlockStorage'

    def __init__(self, name, template, hot_file):
        super(VirtualStorage, self).__init__('OS::Cinder::Volume')
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


"""
class VirtualLink(HOTBase):
    def __init__(self, name, template, hot_file):
        super().__init__('OS::Neutron::ProviderNet')
        self.properties = {
            'name': template['properties']['vl_profile']['network_name']
        }
        if 'network_type' in template['properties']['vl_profile']:
            self.properties['network_type'] = template['properties']['vl_profile']['network_type']
        if 'physical_network' in template['properties']['vl_profile']:
            self.properties['physical_network'] = template['properties']['vl_profile']['physical_network']
        if 'provider_segmentation_id' in template['properties']['vl_profile']:
            self.properties['segmentation_id'] = template['properties']['vl_profile']['provider_segmentation_id']

        _change_input_to_param(self.properties)
        hot_file['resources'][name] = {
            'type': self.type,
            'properties': self.properties
        }
"""


class VirtualPort(HOTBase):
    def __init__(self, name, template, hot_file, node_templates):
        super().__init__('OS::Neutron::Port')
        network = None
        for requirement in template['requirements']:
            if 'virtual_binding' in requirement:
                pass
            if 'virtual_link' in requirement:
                network = node_templates[requirement['virtual_link']]['properties']['vl_profile']['network_name']
        if network is None:
            raise PackageNotValid('network未定义')

        self.properties = {
            'network': network,
        }
        if 'vnic_type' in template['properties']:
            self.properties['binding:vnic_type'] = template['properties']['vnic_type']
        if 'port_security_enabled' in template['properties']:
            self.properties['port_security_enabled'] = template['properties']['port_security_enabled']
        _change_input_to_param(self.properties)
        hot_file['resources'][name] = {
            'type': self.type,
            'properties': self.properties
        }
