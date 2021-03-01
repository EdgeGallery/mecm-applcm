# -*- coding: utf-8 -*-
import re

def get_hot_yaml_path(unzip_pkg_path):

    pass


class CsarPkg(object):
    _TOSCA_METADATA_PATH = 'TOSCA-Metadata/TOSCA.meta'
    _APPD_R = '^Entry-Definitions: (.*)$'

    def __init__(self, pkg_path):
        self.pkg_path = pkg_path
        with open(self.pkg_path + '/' + self._TOSCA_METADATA_PATH, 'r') as meta:
            for line in meta.readlines():
                if line.startswith('Entry-Definitions: '):
                    match = re.match(self._APPD_R, line)
                    self._APPD_PATH = match.group(1)
                    break

    def translate(self):
        pass
