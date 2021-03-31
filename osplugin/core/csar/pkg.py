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

from core.exceptions import PackageNotValid
from core.log import logger
from core.openstack_utils import TOSCA_TYPE_CLASS

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


class CsarPkg:
    """
    csar包
    """

    def __init__(self, pkg_path):
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
            'description': 'this is an example',
            'resources': {},
            'parameters': appd['topology_template']['inputs'],
            'outputs': {}
        }
        for name, template in appd['topology_template']['node_templates'].items():
            if template['type'] in TOSCA_TYPE_CLASS:
                TOSCA_TYPE_CLASS[template['type']](name,
                                                   template,
                                                   hot,
                                                   appd['topology_template']['node_templates'])
            else:
                LOG.info('skip unknown tosca type %s', template['type'])

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
