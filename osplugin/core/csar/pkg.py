# -*- coding: utf-8 -*-
import logging
import os
import re
import zipfile

import yaml

from core.exceptions import PackageNotValid
from core.openstack_utils import NovaServer, VirtualStorage, VirtualPort, VirtualLink

_TOSCA_METADATA_PATH = 'TOSCA-Metadata/TOSCA.meta'
_APPD_TOSCA_METADATA_PATH = 'TOSCA_VNFD.meta'
_APPD_R = '^Entry-Definitions: (.*)$'


def get_hot_yaml_path(unzip_pkg_path):
    csar_pkg = CsarPkg(unzip_pkg_path)
    return csar_pkg.hot_path


def _translate(appd, base_path):
    hot = {
        'heat_template_version': '2015-04-30',
        'description': 'this is an example',
        'resources': {},
        'parameters': appd['topology_template']['inputs'],
        'outputs': []
    }
    for name, template in appd['topology_template']['node_templates'].items():
        if template['type'] == 'tosca.nodes.nfv.VNF':
            pass
        elif template['type'] == 'tosca.nodes.nfv.Vdu.Compute':
            NovaServer(name, template, hot, appd['topology_template']['node_templates'])
        elif template['type'] == 'tosca.nodes.nfv.VduCp':
            VirtualPort(name, template, hot)
        elif template['type'] == 'tosca.nodes.nfv.VnfVirtualLink':
            VirtualLink(name, template, hot)
        elif template['type'] == 'tosca.nodes.nfv.Vdu.VirtualBlockStorage':
            VirtualStorage(name, template, hot)
        elif template['type'] == 'tosca.nodes.nfv.app.configuration':
            pass
        else:
            logging.info('skip unknown tosca type %s', template['type'])

    for name, group in appd['topology_template']['groups'].items():
        if group['type'] == 'tosca.groups.nfv.PlacementGroup':
            pass
        else:
            logging.info('skip unknown tosca type %s', group['type'])

    for policy in appd['topology_template']['policies']:
        for key, value in policy.items():
            if value['type'] == 'tosca.policies.nfv.AntiAffinityRule':
                pass
            else:
                logging.info('skip unknow tosca type %s', value['type'])

    with open(base_path + '/hot.yaml', 'w') as f:
        yaml.dump(hot, f)

    return base_path + '/hot.yaml'


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
        appd_file_path = self.base_dir + '/' + self._APPD_PATH
        appd_file_dir = os.path.dirname(appd_file_path)
        if appd_file_path.endswith('.zip'):
            try:
                with zipfile.ZipFile(appd_file_path) as zip_file:
                    namelist = zip_file.namelist()
                    for f in namelist:
                        zip_file.extract(f, appd_file_dir)
            except Exception as e:
                logging.error(e)
            cmcc_appd = CmccAppD(appd_file_dir)
            self.hot_path = _translate(cmcc_appd.appd, appd_file_dir)
        elif appd_file_path.endswith('.yaml'):
            simple_appd = yaml.load(appd_file_path, Loader=yaml.FullLoader)
            self.hot_path = _translate(simple_appd, appd_file_dir)
        else:
            logging.error('不支持的appd类型')


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
