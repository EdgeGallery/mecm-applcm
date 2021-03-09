# -*- coding: utf-8 -*-
import re

from heatclient.v1.client import Client as HeatClient
from keystoneauth1 import identity, session
from novaclient import client as nova_client
import config
from core.exceptions import PackageNotValid
from core.custom_glance_client import CustomGlanceClient

RC_FILE_DIR = config.base_dir + '/config'


def get_rc(host_ip):
    rc_file_path = RC_FILE_DIR + '/' + host_ip
    return RCFile(rc_file_path)


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
    return session.Session(auth=get_auth(host_ip))


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
    sess = session.Session(auth=auth)
    return HeatClient(session=sess, endpoint_override=rc.heat_url)


def create_nova_client(host_ip):
    return nova_client.Client('2', session=get_session(host_ip))


def create_glance_client(host_ip):
    asession = get_session(host_ip)
    return CustomGlanceClient(session=asession)


class RCFile(object):
    _PATTERN = r'^export (.+)=(.+)$'

    user_domain_name = 'Default'
    project_domain_name = 'Default'
    username = None
    password = None
    project_name = None
    auth_url = None
    heat_url = None

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


class HOTBase(object):
    def __init__(self, hot_type):
        self.type = hot_type


def _get_flavor(template):
    cpu = str(template['capabilities']['virtual_compute']['properties']['virtual_cpu']['num_virtual_cpu'])
    memory = str(template['capabilities']['virtual_compute']['properties']['virtual_memory'][
                     'virtual_mem_size'])

    return cpu + 'c-' + memory + 'm'


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
            'block_device_mapping_v2': [],
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
                params = {}
                for key, param in template['properties']['bootdata']['user_data']['params'].items():
                    params['$' + key + '$'] = param
                    user_data = {
                        'str_replace': {
                            'template': template['properties']['bootdata']['user_data']['contents'],
                            'params': params
                        }
                    }
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
