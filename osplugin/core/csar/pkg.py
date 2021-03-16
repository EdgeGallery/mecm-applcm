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
from core.openstack_utils import NovaServer, VirtualStorage, VirtualPort

_TOSCA_METADATA_PATH = 'TOSCA-Metadata/TOSCA.meta'
_APPD_TOSCA_METADATA_PATH = 'TOSCA_VNFD.meta'
_APPD_R = '^Entry-Definitions: (.*)$'

LOG = logger


def get_hot_yaml_path(unzip_pkg_path):
    try:
        csar_pkg = CsarPkg(unzip_pkg_path)
    except FileNotFoundError:
        LOG.info('%s 文件不存在', unzip_pkg_path)
        return None
    return csar_pkg.hot_path


class CsarPkg(object):

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
                    self._APPD_PATH = match.group(1)
                    break
        if self._APPD_PATH is None:
            raise PackageNotValid('entry definitions not exist')
        self.appd_file_path = self.base_dir + '/' + self._APPD_PATH
        self.appd_file_dir = os.path.dirname(self.appd_file_path)
        self.hot_path = self.appd_file_dir + '/hot.yaml'

    def _unzip(self):
        try:
            with zipfile.ZipFile(self.appd_file_path) as zip_file:
                namelist = zip_file.namelist()
                for f in namelist:
                    zip_file.extract(f, self.appd_file_dir)
        except Exception as e:
            LOG.error(e, exc_info=True)

    def translate(self):
        self._unzip()
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
            if template['type'] == 'tosca.nodes.nfv.VNF':
                pass
            elif template['type'] == 'tosca.nodes.nfv.Vdu.Compute':
                NovaServer(name, template, hot, appd['topology_template']['node_templates'])
            elif template['type'] == 'tosca.nodes.nfv.VduCp':
                VirtualPort(name, template, hot, appd['topology_template']['node_templates'])
            elif template['type'] == 'tosca.nodes.nfv.VnfVirtualLink':
                # VirtualLink(name, template, hot)
                pass
            elif template['type'] == 'tosca.nodes.nfv.Vdu.VirtualBlockStorage':
                VirtualStorage(name, template, hot)
            elif template['type'] == 'tosca.nodes.nfv.app.configuration':
                pass
            else:
                LOG.info('skip unknown tosca type %s', template['type'])

        for name, group in appd['topology_template']['groups'].items():
            if group['type'] == 'tosca.groups.nfv.PlacementGroup':
                pass
            else:
                LOG.info('skip unknown tosca type %s', group['type'])

        for policy in appd['topology_template']['policies']:
            for key, value in policy.items():
                if value['type'] == 'tosca.policies.nfv.AntiAffinityRule':
                    pass
                else:
                    LOG.info('skip unknow tosca type %s', value['type'])

        with open(self.hot_path, 'w') as file:
            yaml.dump(hot, file)


class CmccAppD(object):
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
