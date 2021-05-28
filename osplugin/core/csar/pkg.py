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
import os
import re
import zipfile

import yaml
from pony.orm import db_session

import utils
from core.csar import sw_image
from core.exceptions import PackageNotValid
from core.log import logger
from core.models import VmImageInfoMapper
from core.openstack_utils import TOSCA_TYPE_CLASS, \
    TOSCA_GROUP_CLASS, TOSCA_POLICY_CLASS, create_glance_client, get_image_by_name_checksum
from task.image_task import add_import_image_task, create_image_record, add_upload_image_task

_TOSCA_METADATA_PATH = 'TOSCA-Metadata/TOSCA.meta'
_APPD_TOSCA_METADATA_PATH = 'TOSCA_VNFD.meta'
_APPD_R = '^Entry-Definitions: (.*)$'

LOG = logger


def get_hot_yaml_path(unzip_pkg_path):
    """
    获取hot模板路径
    :param unzip_pkg_path: 包解压路径
    :return: hot模板路径
    """
    try:
        csar_pkg = CsarPkg(unzip_pkg_path)
    except FileNotFoundError:
        LOG.info('%s 文件不存在', unzip_pkg_path)
        return None
    return csar_pkg.hot_path


def _set_default_security_group(appd):
    topology_template = appd['topology_template']
    if 'ue_ip_segment' not in topology_template['inputs'] \
            and 'mep_ip' not in topology_template['inputs']:
        return
    if 'groups' not in topology_template:
        topology_template['groups'] = {}
    topology_template['groups']['DefaultSecurityGroup'] = {
        'type': 'tosca.groups.nfv.PortSecurityGroup',
        'properties': {
            'description': 'default security group',
            'name': 'app-group'
        },
        'members': []
    }
    for name, template in topology_template['node_templates'].items():
        if template['type'] == 'tosca.nodes.nfv.VduCp':
            topology_template['groups']['DefaultSecurityGroup']['members'] \
                .append(name)
    if 'policies' not in topology_template:
        topology_template['policies'] = {}
    if 'ue_ip_segment' in topology_template['inputs']:
        topology_template['policies']['n6_rule'] = {
            'type': 'tosca.policies.nfv.SecurityGroupRule',
            'targets': ['DefaultSecurityGroup'],
            'properties': {
                'protocol': 0,
                'remote_ip_prefix': {
                    'get_input': 'ue_ip_segment'
                }
            }
        }
    if 'mep_ip' in topology_template['inputs']:
        topology_template['policies']['mp1_rule'] = {
            'type': 'tosca.policies.nfv.SecurityGroupRule',
            'targets': ['DefaultSecurityGroup'],
            'properties': {
                'protocol': 0,
                'remote_ip_prefix': {
                    'concat': [
                        {
                            'get_input': 'mep_ip'
                        },
                        '/32'
                    ]
                }
            }
        }


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
        self.appd_file_dir = os.path.dirname(self.appd_file_path)
        self.hot_path = self.appd_file_dir + '/hot.yaml'

    def unzip(self):
        """
        解压csar包
        """
        with zipfile.ZipFile(self.appd_file_path) as zip_file:
            namelist = zip_file.namelist()
            for file in namelist:
                zip_file.extract(file, self.appd_file_dir)

    @db_session
    def check_image(self, host_ip):
        image_id_map = {}
        for sw_image_desc in self.sw_image_desc_list:
            image = VmImageInfoMapper.get(host_ip=host_ip, checksum=sw_image_desc.checksum)
            if image is not None:
                image_id_map[sw_image_desc.name] = image.image_id
            else:
                if sw_image_desc.sw_image is None or sw_image_desc.sw_image == '':
                    image = get_image_by_name_checksum(sw_image_desc.name,
                                                       sw_image_desc.checksum,
                                                       host_ip)
                    if image is None:
                        raise RuntimeError(f'image {sw_image_desc.name} 不存在')
                    image_id_map[sw_image_desc.name] = image['id']

                elif sw_image_desc.sw_image.startswith('http'):
                    image_id = create_image_record(sw_image_desc,
                                                   self.app_package_id,
                                                   host_ip)
                    image_id_map[sw_image_desc.name] = image_id
                    add_import_image_task(image_id, host_ip, sw_image_desc.sw_image)
                else:
                    image_id = create_image_record(sw_image_desc,
                                                   self.app_package_id,
                                                   host_ip)
                    image_id_map[sw_image_desc.name] = image_id
                    zip_index = sw_image_desc.sw_image.find('.zip')
                    zip_file_path = self.base_dir + '/' + sw_image_desc.sw_image[0: zip_index+4]
                    img_tmp_dir = f'/tmp/osplugin/images/{image_id}'
                    img_tmp_file = img_tmp_dir + sw_image_desc.sw_image[zip_index+4:]
                    logger.info(f'image dir {img_tmp_file}')
                    if not utils.exists_path(img_tmp_dir):
                        utils.unzip(zip_file_path, img_tmp_dir)
                    add_upload_image_task(image_id, host_ip, img_tmp_file)

        self.image_id_map = image_id_map

    def translate(self):
        """
        转换csar包为hot
        """
        self.unzip()
        if self.appd_file_path.endswith('.zip'):
            cmcc_appd = CmccAppD(self.appd_file_dir)
            appd = cmcc_appd.appd
        elif self.appd_file_path.endswith('.yaml'):
            appd = yaml.load(self.appd_file_path, Loader=yaml.FullLoader)
        else:
            raise PackageNotValid('不支持的appd类型')

        hot = {
            'heat_template_version': '2015-04-30',
            'description': 'Generated By OsPlugin',
            'resources': {},
            'parameters': appd['topology_template']['inputs'],
            'outputs': {}
        }

        # 默认安全组规则
        _set_default_security_group(appd)

        for name, template in appd['topology_template']['node_templates'].items():
            if template['type'] in TOSCA_TYPE_CLASS:
                resource = TOSCA_TYPE_CLASS[template['type']](name,
                                                              template)
                resource.set_properties(topology_template=appd['topology_template'],
                                        hot_file=hot,
                                        image_id_map=self.image_id_map)
            else:
                LOG.info('skip unknown tosca type %s', template['type'])

        for name, group in appd['topology_template']['groups'].items():
            if group['type'] in TOSCA_GROUP_CLASS:
                resource = TOSCA_GROUP_CLASS[group['type']](name, group)
                resource.set_properties(topology_template=appd['topology_template'],
                                        hot_file=hot)

        for name, policy in appd['topology_template']['policies'].items():
            if policy['type'] in TOSCA_POLICY_CLASS:
                resource = TOSCA_POLICY_CLASS[policy['type']](name, policy)
                resource.set_properties(topology_template=appd['topology_template'],
                                        hot_file=hot)

        with open(self.hot_path, 'w') as file:
            yaml.dump(hot, file)


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
