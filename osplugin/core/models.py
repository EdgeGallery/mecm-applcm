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
import zipfile

from pony.orm import PrimaryKey, Required, Optional

import config
import utils
from core.csar.pkg import get_hot_yaml_path
from core.exceptions import ParamNotValid
from core.log import logger
from core.orm.adapter import db

_APP_TASK_PATH = config.base_dir + '/tmp/tasks'
LOG = logger


class UploadPackageRequest(object):
    accessToken = None
    hostIp = None
    app_package_id = None
    tenant_id = None

    def __init__(self, request_iterator):
        task_id = utils.gen_uuid()
        self._tmp_package_dir = _APP_TASK_PATH + '/' + task_id
        utils.create_dir(self._tmp_package_dir)
        self.tmp_package_file_path = self._tmp_package_dir + '/package.zip'
        for request in request_iterator:
            if request.accessToken:
                self.accessToken = request.accessToken
            elif request.appPackageId:
                self.app_package_id = request.appPackageId
            elif request.hostIp:
                self.hostIp = request.hostIp
            elif request.tenantId:
                self.tenant_id = request.tenantId
            elif request.package:
                with open(self.tmp_package_file_path, 'ab') as f:
                    f.write(request.package)

    def delete_tmp(self):
        utils.delete_dir(self._tmp_package_dir)


class InstantiateRequest(object):
    accessToken = None
    hostIp = None
    app_instance_id = None
    app_package_id = None
    ak = None
    sk = None
    app_package_path = None

    def __init__(self, request):
        self.accessToken = request.accessToken
        self.app_instance_id = request.appInstanceId
        self.hostIp = request.hostIp
        self.app_package_id = request.appPackageId
        self.app_package_path = config.base_dir + '/package/' + request.appPackageId
        self.ak = request.ak
        self.sk = request.sk


class UploadCfgRequest(object):
    accessToken = None
    hostIp = None
    config_file = None

    def __init__(self, request_iterator):
        for request in request_iterator:
            if request.accessToken:
                self.accessToken = request.accessToken
            elif request.hostIp:
                self.hostIp = request.hostIp
            elif request.configFile:
                self.config_file = request.configFile


"""
数据库定义
"""


class AppInsMapper(db.Entity):
    _table_ = 't_app_instance'
    app_instance_id = PrimaryKey(str, max_len=64)
    host_ip = Required(str, max_len=15)
    stack_id = Required(str, max_len=64, unique=True)
    operational_status = Required(str, max_len=128)
    operation_info = Optional(str, max_len=256, nullable=True)


class VmImageInfoMapper(db.Entity):
    _table_ = 't_vm_image_info'
    app_instance_id = Required(str, max_len=64)
    host_ip = Required(str, max_len=15)
    vm_id = Required(str, max_len=64)
    image_id = Required(str, max_len=64)
    image_name = Required(str, max_len=64)
    image_size = Required(int, size=64)


db.generate_mapping(create_tables=True)
