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

from pony.orm import PrimaryKey, Required, Optional, select

import utils
from core.log import logger
from core.orm.adapter import db

_APP_TASK_PATH = '/tmp/osplugin/tasks'
LOG = logger


class UploadPackageRequest:
    """
    上传请求体封装
    """
    accessToken = None
    hostIp = None
    tenantId = None
    appPackageId = None

    def __init__(self, request_iterator):
        task_id = utils.gen_uuid()
        self._tmp_package_dir = _APP_TASK_PATH + '/' + task_id
        utils.create_dir(self._tmp_package_dir)
        self._tmp_package_file = self._tmp_package_dir + '/package.zip'
        with open(self._tmp_package_file, 'ab') as file:
            for request in request_iterator:
                if request.accessToken:
                    self.accessToken = request.accessToken
                elif request.appPackageId:
                    self.appPackageId = request.appPackageId
                elif request.hostIp:
                    self.hostIp = request.hostIp
                elif request.tenantId:
                    self.tenantId = request.tenantId
                elif request.package:
                    file.write(request.package)

    def delete_tmp(self):
        """
        删除临时文件
        """
        utils.delete_dir(self._tmp_package_dir)

    def unzip(self, app_package_path):
        """
        解压app包到包目录
        Args:
            app_package_path:

        Returns:

        """
        utils.unzip(self._tmp_package_file, app_package_path)

    def get_tmp_file_path(self):
        """
        获取临时文件目录
        """
        return self.tmpPackageFilePath


_APP_PACKAGE_PATH_FORMATTER = '{base_dir}/package/{host_ip}/{app_package_id}'


class UploadCfgRequest:
    """
    配置上传请求体封装
    """
    accessToken = None
    hostIp = None
    tenantId = None
    configFile = None

    def __init__(self, request_iterator):
        for request in request_iterator:
            self.accessToken = request.accessToken if request.accessToken else self.accessToken
            self.hostIp = request.hostIp if request.hostIp else self.hostIp
            self.tenantId = request.tenantId if request.tenantId else self.tenantId
            self.configFile = request.configFile if request.configFile else self.tenantId

    def get_config_file(self):
        """
        get config file
        Returns:

        """
        return self.configFile

    def get_host_ip(self):
        """
        get host ip
        Returns:

        """
        return self.hostIp


class AppInsMapper(db.Entity):
    """
    t_app_instance表映射
    """
    _table_ = 't_app_instance'
    app_instance_id = PrimaryKey(str, max_len=64)
    host_ip = Required(str, max_len=15)
    tenant_id = Required(str, max_len=64)
    stack_id = Required(str, max_len=64, unique=True)
    operational_status = Required(str, max_len=128)
    operation_info = Optional(str, nullable=True)

    def get_table_name(self):
        """
        get table name
        Returns:

        """
        return self._table_

    def get_key(self):
        """
        get key
        Returns:

        """
        return self.app_instance_id


class AppPkgMapper(db.Entity):
    """
    t_app_package表
    """
    _table_ = 't_app_package'
    app_package_id = Required(str, max_len=64)
    host_ip = Required(str, max_len=15)
    status = Required(str, max_len=10)
    app_package_path = Optional(str, max_len=255)


class VmImageInfoMapper(db.Entity):
    """
    t_vm_image_info表映射
    """
    _table_ = 't_vm_image_info'
    image_id = Required(str, max_len=64)
    host_ip = Required(str, max_len=15)
    image_name = Required(str, max_len=64)
    status = Required(str, max_len=20)
    disk_format = Required(str, max_len=20)
    tenant_id = Required(str, max_len=64)

    image_size = Optional(int, size=64)
    checksum = Optional(str, max_len=64)

    app_package_id = Optional(str, max_len=64)
    compress_task_id = Optional(str, max_len=64)
    compress_task_status = Optional(str, max_len=20)
    remote_url = Optional(str)

    def get_table_name(self):
        """
        get table name
        Returns:

        """
        return self._table_

    @classmethod
    def find_many(cls, **kwargs):
        """
        根据查询条件查询多个实例对象
        :return:
        """
        result = select(x for x in cls)
        for (key, value) in kwargs.items():
            result = result.filter(lambda x: getattr(x, key) == value)
        return result


db.generate_mapping(create_tables=True)
