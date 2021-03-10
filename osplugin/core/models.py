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

from pony.orm import PrimaryKey, Required, Optional

import config
import utils
from core.orm.adapter import db

_APP_TASK_PATH = config.base_dir + '/tmp/tasks'


class InstantiateRequest(object):
    accessToken = None
    app_instance_id = None
    hostIp = None
    ak = None
    sk = None
    app_package_path = None

    def __init__(self, request_iterator):
        self._task_path = _APP_TASK_PATH + '/' + utils.gen_uuid()
        utils.create_dir(self._task_path)
        for request in request_iterator:
            if request.accessToken:
                self.accessToken = request.accessToken
            elif request.appInstanceId:
                self.app_instance_id = request.appInstanceId
            elif request.hostIp:
                self.hostIp = request.hostIp
            elif request.package:
                self.app_package_path = self._task_path + '/package.zip'
                with open(self.app_package_path, 'ab') as package_file:
                    package_file.write(request.package)
            elif request.ak:
                self.ak = request.ak
            elif request.sk:
                self.sk = request.sk

    def delete_package_tmp(self):
        utils.delete_dir(self._task_path)
        self.app_package_path = None


class UploadCfgRequest(object):
    accessToken = None
    hostIp = None
    config_file = None

    def __init__(self, request_iterator):
        for request in request_iterator:
            if request.accessToken:
                self.accessToken = request.accessToken
            elif request.appInstanceId:
                self.app_instance_id = request.appInstanceId
            elif request.hostIp:
                self.hostIp = request.hostIp
            elif request.config_file:
                self.config_file = request.config_file


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
