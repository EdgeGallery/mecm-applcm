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
from core.tosca import translator
from core.csar import sw_image, tosca_utils
from core.csar.tosca_utils import get_data
from core.exceptions import PackageNotValid
from core.log import logger
from core.models import VmImageInfoMapper
from core.openstack_utils import get_image_by_name_checksum, create_neutron_client
from task.image_task import add_import_image_task, create_image_record, add_upload_image_task

_TOSCA_METADATA_PATH = 'TOSCA-Metadata/TOSCA.meta'
_APPD_TOSCA_METADATA_PATH = 'TOSCA_VNFD.meta'
_APPD_R = '^Entry-Definitions: (.*)$'

LOG = logger


def set_network_then_return_yaml(host_ip, tenant_id, app_package_id, app_package_path, parameters):
    LOG.debug('读取包')
    try:
        csar_pkg = CsarPkg(app_package_id, app_package_path)
    except FileNotFoundError:
        LOG.info('%s 文件不存在', app_package_path)
        return None

    LOG.debug('读取hot文件')
    hot_yaml_path = csar_pkg.hot_path
    if hot_yaml_path is None:
        LOG.error("get hot yaml path failure, app package might not active")
        return None

    LOG.debug('创建tosca network')
    csar_pkg.create_request_networks(host_ip, tenant_id, parameters)

    return hot_yaml_path


def _set_default_security_group(appd):
    """
    注入默认安全组和安全组规则
    """
    topology_template = appd['topology_template']

    default_group = tosca_utils.APP_SECURITY_GROUP_NAME

    # 设置默认安全组
    topology_template['groups'][default_group] = tosca_utils.app_security_group()
    for name, template in topology_template['node_templates'].items():
        if template['type'] != 'tosca.nodes.nfv.VduCp':
            continue
        topology_template['groups'][default_group]['members'].append(name)

    # 设置默认安全策略
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
        template['properties']['sw_image_data']['name'] = 'empty-disk'
        volume_node_name = node_name + '_CDROM'
        volume_size = int(image_id_map[image]['size'] / 1000000000) + 1
        properties = {
            'virtual_storage_data': {
                'type_of_storage': 'block_storage',
                'size_of_storage': volume_size
            },
            'sw_image_data': {'name': image},
        }
        if 'nfvi_constraints' in template['properties']:
            properties['nfvi_constraints'] = template['properties']['nfvi_constraints']
        volume_templates[volume_node_name] = {
            'type': 'tosca.nodes.nfv.Vdu.VirtualStorage',
            'properties': properties
        }
    topology_template['node_templates'].update(volume_templates)


def _set_ak_sk(appd):
    inputs = appd['topology_template']['inputs']
    if 'ak' not in inputs or 'sk' not in inputs:
        return
    for node_template in appd['topology_template']['node_templates'].values():
        if node_template['type'] != 'tosca.nodes.nfv.Vdu.Compute':
            continue
        if 'user_data' not in node_template['properties']['bootdata']:
            node_template['properties']['bootdata']['user_data'] = {
                'contents': '#!/bin/bash',
                'params': {}
            }
        user_data = node_template['properties']['bootdata']['user_data']
        mec_runtime_script = '\necho "ak=$ak$\\nsk=$sk$\\n" >> /root/init.txt\n'
        user_data['params']['ak'] = {'get_input': 'ak'}
        user_data['params']['sk'] = {'get_input': 'sk'}
        user_data['contents'] = user_data['contents'] + mec_runtime_script


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

        # Default security group rules
        _set_default_security_group(appd)
        _set_iso_cdrom(appd, self.image_id_map)
        _set_ak_sk(appd)

        LOG.debug('app descriptions:\n%s', yaml.dump(appd, Dumper=yaml.SafeDumper))

        hot = translator.translate(appd, self.image_id_map)

        with open(self.hot_path, 'w') as file:
            yaml.dump(data=hot, stream=file, Dumper=yaml.SafeDumper)

    def create_request_networks(self, host_ip, tenant_id, parameters):
        if self.appd_file_path.endswith('.zip'):
            cmcc_appd = CmccAppD(os.path.dirname(self.appd_file_path))
            appd = cmcc_appd.appd
        elif self.appd_file_path.endswith('.yaml'):
            appd = yaml.load(self.appd_file_path, Loader=yaml.FullLoader)
        else:
            raise PackageNotValid('不支持的appd类型')

        neutron = create_neutron_client(host_ip, tenant_id)

        inputs = appd['topology_template']['inputs']

        for name, template in appd['topology_template']['node_templates'].items():
            if template['type'] != 'tosca.nodes.nfv.VnfVirtualLink':
                continue
            network_properties = translator.translate_vl(template,
                                                         inputs=inputs,
                                                         parameters=parameters)
            network = neutron.create_network({'network': network_properties['network']})
            LOG.info('created not exist network %s id: %s', network['network']['name'], network['network']['id'])
            for subnet in network_properties['subnets']:
                subnet['network_id'] = network['network']['id']
                neutron.create_subnet({'subnet': subnet})
                LOG.info('created subnet %s', subnet['cidr'])


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
