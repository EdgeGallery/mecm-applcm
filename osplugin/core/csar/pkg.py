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
import os
import re
import zipfile

import yaml
from pony.orm import db_session

import utils
from core.csar import sw_image, tosca_utils
from core.exceptions import PackageNotValid
from core.log import logger
from core.models import VmImageInfoMapper
from core.openstack_utils import TOSCA_TYPE_CLASS, \
    TOSCA_GROUP_CLASS, TOSCA_POLICY_CLASS, get_image_by_name_checksum, create_neutron_client
from task.image_task import add_import_image_task, create_image_record, add_upload_image_task

_TOSCA_METADATA_PATH = 'TOSCA-Metadata/TOSCA.meta'
_APPD_TOSCA_METADATA_PATH = 'TOSCA_VNFD.meta'
_APPD_R = '^Entry-Definitions: (.*)$'

LOG = logger


def _set_default_security_group(appd):
    """
    注入默认安全组和安全组规则
    """
    topology_template = appd['topology_template']
    if 'inputs' not in topology_template:
        return
    if 'ue_ip_segment' not in topology_template['inputs'] \
            and 'mep_ip' not in topology_template['inputs']:
        return
    default_group = tosca_utils.APP_SECURITY_GROUP_NAME

    # 设置默认安全组
    if 'groups' not in topology_template:
        topology_template['groups'] = {}
    topology_template['groups'][default_group] = tosca_utils.app_security_group()
    for name, template in topology_template['node_templates'].items():
        if template['type'] == 'tosca.nodes.nfv.VduCp':
            topology_template['groups'][default_group]['members'] \
                .append(name)

    # 设置默认安全策略
    if 'policies' not in topology_template:
        topology_template['policies'] = []
    if 'ue_ip_segment' in topology_template['inputs']:
        topology_template['policies'].append(tosca_utils.n6_rule(target=default_group))
    if 'mep_ip' in topology_template['inputs']:
        topology_template['policies'].append(tosca_utils.mp1_rule(target=default_group))


def _set_iso_cdrom(appd, image_id_map):
    """
    把iso格式镜像挂载为cdrom
    Args:
        appd:

    Returns:

    """
    topology_template = appd['topology_template']
    volume_templates = {}
    for node_name, template in topology_template['node_templates'].items():
        if template['type'] != 'tosca.nodes.nfv.Vdu.Compute':
            continue
        image = template['properties']['sw_image_data']['name']
        if image_id_map[image]['format'] != 'iso':
            continue
        node_name = node_name + '_CDROM'
        volume_size = int(image_id_map[image]['size'] / 1000000000) + 1
        properties = {
            'virtual_storage_data': {
                'type_of_storage': 'block_storage',
                'size_of_storage': volume_size
            },
            'sw_image_data': {'name': image},
            'nfvi_constraints': template['properties']['nfvi_constraints']
        }
        if 'nfvi_constraints' in template['properties']:
            properties['nfvi_constraints'] = template['properties']['nfvi_constraints']
        volume_templates[node_name] = {
            'type': 'tosca.nodes.nfv.Vdu.VirtualStorage',
            'properties': properties
        }
    topology_template['node_templates'].update(volume_templates)
    
def _set_default_ip(appd):
    """
    主动注入IP，需要固定cp名称和ip参数
    """
    topology_template = appd['topology_template']
    if 'inputs' not in topology_template:
        return
    inputs = topology_template['inputs']
    node_templates = topology_template['node_templates']
    if 'app_mp1_ip' in inputs and 'EMS_VDU1_CP0' in node_templates:
        node_templates['EMS_VDU1_CP0']['attributes'] = {
            'ipv4_address': {
                'get_input': 'app_mp1_ip'
            }
        }

    if 'app_internet_ip' in inputs and 'EMS_VDU1_CP1' in node_templates:
        node_templates['EMS_VDU1_CP1']['attributes'] = {
            'ipv4_address': {
                'get_input': 'app_internet_ip'
            }
        }

    if 'app_n6_ip' in inputs and 'EMS_VDU1_CP2' in node_templates:
        node_templates['EMS_VDU1_CP2']['attributes'] = {
            'ipv4_address': {
                'get_input': 'app_n6_ip'
            }
        }


def _input_translate(inputs):
    """
    处理cmcc输入类型，把text/password类型转换为string
    Args:
        inputs:

    Returns:

    """
    result = copy.deepcopy(inputs)
    for key in result.keys():
        if result[key]['type'] == 'text' or result[key]['type'] == 'password':
            result[key]['type'] = 'string'
    return result


class CsarPkg:
    """
    csar包
    """

    def __init__(self, app_package_id, pkg_path):
        self.app_package_id = app_package_id
        dirs = os.listdir(pkg_path)
        if len(dirs) == 1:
            self.base_dir = pkg_path + '/' + dirs[0]
        else:
            self.base_dir = pkg_path
        with open(self.base_dir + '/' + _TOSCA_METADATA_PATH, 'r') as meta:
            for line in meta.readlines():
                if line.startswith('Entry-Definitions: '):
                    match = re.match(_APPD_R, line)
                    self._appd_path = match.group(1)
                    break
        sw_image_desc_path = self.base_dir + '/Image/SwImageDesc.json'
        self.sw_image_desc_list = sw_image.get_sw_image_desc_list(sw_image_desc_path)
        self.image_id_map = {}
        if self._appd_path is None:
            raise PackageNotValid('entry definitions not exist')
        self.appd_file_path = self.base_dir + '/' + self._appd_path
        self.hot_path = os.path.dirname(self.appd_file_path) + '/hot.yaml'

    def unzip(self):
        """
        解压csar包
        """
        with zipfile.ZipFile(self.appd_file_path) as zip_file:
            namelist = zip_file.namelist()
            for file in namelist:
                zip_file.extract(file, os.path.dirname(self.appd_file_path))

    @db_session
    def check_image(self, host_ip, tenant_id):
        """
        根据sw_image_desc.json检查镜像，如果不存在，根据类型创建镜像
        """
        image_id_map = {}
        for sw_image_desc in self.sw_image_desc_list:
            image = VmImageInfoMapper.get(host_ip=host_ip, checksum=sw_image_desc['checksum'])
            if image is not None:
                LOG.debug('use exist image')
                image_id_map[sw_image_desc['name']] = {
                    'id': image.image_id,
                    'format': image.disk_format,
                    'size': image.image_size
                }
                continue

            image = get_image_by_name_checksum(sw_image_desc['name'],
                                               sw_image_desc['checksum'],
                                               host_ip,
                                               tenant_id)
            if image is not None:
                LOG.debug('use image from os')
                image_id_map[sw_image_desc['name']] = {
                    'id': image['id'],
                    'format': image['disk_format'],
                    'size': image['size']
                }
            elif sw_image_desc['swImage'].startswith('http'):
                LOG.debug('use image from remote')
                image_id = create_image_record(sw_image_desc,
                                               self.app_package_id,
                                               host_ip,
                                               tenant_id)
                image_id_map[sw_image_desc['name']] = {
                    'id': image_id,
                    'format': sw_image_desc['diskFormat'],
                    'size': sw_image_desc['size']
                }
                add_import_image_task(image_id, host_ip, sw_image_desc['swImage'])
            else:
                LOG.debug('use image from local')
                image_id = create_image_record(sw_image_desc,
                                               self.app_package_id,
                                               host_ip,
                                               tenant_id)
                image_id_map[sw_image_desc['name']] = {
                    'id': image_id,
                    'format': sw_image_desc['diskFormat'],
                    'size': sw_image_desc['size']
                }
                zip_index = sw_image_desc['swImage'].find('.zip')
                if zip_index != -1:
                    zip_file_path = self.base_dir + '/' + sw_image_desc['swImage'][0: zip_index + 4]
                    img_tmp_dir = f'/tmp/osplugin/images/{self.app_package_id}'
                    img_tmp_file = img_tmp_dir + sw_image_desc['swImage'][zip_index + 4:]
                    logger.debug('image dir %s', img_tmp_file)
                    if not utils.exists_path(img_tmp_dir):
                        utils.unzip(zip_file_path, img_tmp_dir)
                else:
                    img_tmp_file = self.base_dir + '/' + sw_image_desc['swImage']
                add_upload_image_task(image_id, host_ip, img_tmp_file) \
                    .add_done_callback(lambda future, path=img_tmp_file: utils.delete_dir(path))

        self.image_id_map = image_id_map

    def translate(self):
        """
        转换csar包为hot
        """
        self.unzip()
        if self.appd_file_path.endswith('.zip'):
            cmcc_appd = CmccAppD(os.path.dirname(self.appd_file_path))
            appd = cmcc_appd.appd
        elif self.appd_file_path.endswith('.yaml'):
            appd = yaml.load(self.appd_file_path, Loader=yaml.FullLoader)
        else:
            raise PackageNotValid('不支持的appd类型')

        hot = {
            'heat_template_version': '2016-10-14',
            'description': 'Generated By OsPlugin',
            'parameters': {},
            'resources': {},
            'outputs': {}
        }
        if 'inputs' in appd['topology_template']:
            hot['parameters'] = _input_translate(appd['topology_template']['inputs'])

        # 设置ip，临时性
        # _set_default_ip(appd)
        # Default security group rules
        _set_default_security_group(appd)

        # ISO image to volume
        _set_iso_cdrom(appd, self.image_id_map)

        self._translate_topology_template(appd, hot)

        with open(self.hot_path, 'w') as file:
            yaml.dump(data=hot, stream=file, Dumper=yaml.SafeDumper)

    def _translate_topology_template(self, appd, hot):
        """
        翻译topology template
        Args:
            appd:
            hot:

        Returns:

        """
        for name, template in appd['topology_template']['node_templates'].items():
            if template['type'] in TOSCA_TYPE_CLASS:
                resource = TOSCA_TYPE_CLASS[template['type']](name,
                                                              template)
                resource.set_properties(topology_template=appd['topology_template'],
                                        hot_file=hot,
                                        image_id_map=self.image_id_map)
            else:
                LOG.info('skip unknown tosca type %s', template['type'])

        if 'groups' in appd['topology_template']:
            for name, group in appd['topology_template']['groups'].items():
                if group['type'] in TOSCA_GROUP_CLASS:
                    resource = TOSCA_GROUP_CLASS[group['type']](name, group)
                    resource.set_properties(topology_template=appd['topology_template'],
                                            hot_file=hot)

        if 'policies' in appd['topology_template']:
            for policy in appd['topology_template']['policies']:
                for name, policy_template in policy.items():
                    if policy_template['type'] in TOSCA_POLICY_CLASS:
                        resource = TOSCA_POLICY_CLASS[policy_template['type']](name, policy_template)
                        resource.set_properties(topology_template=appd['topology_template'],
                                                hot_file=hot)

    def create_request_networks(self, host_ip, tenant_id):
        if self.appd_file_path.endswith('.zip'):
            cmcc_appd = CmccAppD(os.path.dirname(self.appd_file_path))
            appd = cmcc_appd.appd
        elif self.appd_file_path.endswith('.yaml'):
            appd = yaml.load(self.appd_file_path, Loader=yaml.FullLoader)
        else:
            raise PackageNotValid('不支持的appd类型')

        neutron = create_neutron_client(host_ip, tenant_id)

        for name, template in appd['topology_template']['node_templates'].items():
            if not template['type'] == 'tosca.nodes.nfv.VnfVirtualLink':
                continue
            vl_profile = template['properties']['vl_profile']
            networks = neutron.list_networks(name=vl_profile['network_name'])
            if len(networks) != 0:
                continue
            network_data = {
                'name': vl_profile['network_name'],
                'shared': False,
                'is_default': False
            }
            segment = {}
            if getattr(vl_profile, 'network_type', None):
                segment['provider_network_type'] = vl_profile['network_type']
            if getattr(vl_profile, 'physical_network', None):
                segment['provider_physical_network'] = vl_profile['physical_network']
            if getattr(vl_profile, 'provider_segmentation_id', None):
                segment['provider_segmentation_id'] = vl_profile['provider_segmentation_id']
            if len(segment.keys()) > 0:
                network_data['segments'] = [segment]
            if 'router_external' in vl_profile:
                network_data['router:external'] = vl_profile['router_external']
            network = neutron.create_network({'network': network_data})
            if 'l3_protocol_data' in template['properties']['vl_profile'] \
                    and len(template['properties']['vl_profile']['l3_protocol_data']) > 0:
                for l3_protocol_data in template['properties']['vl_profile']['l3_protocol_data']:
                    subnet = {
                        'cidr': l3_protocol_data['cidr'],
                        'network_id': network['id'],
                        'ip_version': l3_protocol_data['ip_version']
                    }
                    if 'name' in l3_protocol_data:
                        subnet['name'] = l3_protocol_data['name']
                    if 'gateway_ip' in l3_protocol_data:
                        subnet['gateway_ip'] = l3_protocol_data['gateway_ip']
                    if 'dhcp_enabled' in l3_protocol_data:
                        subnet['dhcp_enabled'] = l3_protocol_data['dhcp_enabled']
                    if 'ipv6_ra_mode' in l3_protocol_data:
                        subnet['ipv6_ra_mode'] = l3_protocol_data['ipv6_ra_mode']
                    if 'ipv6_address_mode' in l3_protocol_data:
                        subnet['ipv6_address_mode'] = l3_protocol_data['ipv6_address_mode']
                    if 'dns_name_servers' in l3_protocol_data:
                        subnet['dns_name_servers'] = l3_protocol_data['dns_name_servers']
                    if 'ip_allocation_pools' in l3_protocol_data:
                        subnet['allocation_pools'] = []
                        for ip_allocation_pool in l3_protocol_data['ip_allocation_pools']:
                            subnet['allocation_pools'].append({
                                'start': ip_allocation_pool['start_ip_address'],
                                'end': ip_allocation_pool['end_ip_address']
                            })
                    if 'host_routes' in l3_protocol_data:
                        subnet['host_routes'] = l3_protocol_data['host_routes']
                    neutron.create_subnet({'subnet': subnet})


class CmccAppD:
    """
    中国移动appd
    """

    def __init__(self, path):
        dirs = os.listdir(path)
        if len(dirs) == 1:
            self.base_dir = path + '/' + dirs[0]
        else:
            self.base_dir = path
        meta_path = self.base_dir + '/' + _APPD_TOSCA_METADATA_PATH
        with open(meta_path) as meta:
            for line in meta.readlines():
                if line.startswith('Entry-Definitions: '):
                    match = re.match(_APPD_R, line)
                    self.appd_file_path = self.base_dir + '/' + match.group(1)
                    break
        with open(self.appd_file_path, 'r') as appd_file:
            self.appd = yaml.load(appd_file, Loader=yaml.FullLoader)

    def get_path(self):
        """
        获取路径
        """
        return self.appd_file_path

    def get_appd(self):
        """
        获取appd
        """
        return self.appd
