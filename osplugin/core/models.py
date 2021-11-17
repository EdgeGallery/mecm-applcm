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

import config
import utils
from core.log import logger
from core.orm.adapter import db

_APP_TASK_PATH = '/tmp/osplugin/tasks'
LOG = logger


class BaseRequest:
    """
    基础请求参数
    """
    access_token = None
    host_ip = None

    def __init__(self, request):
        self.access_token = request.accessToken
        self.host_ip = request.hostIp

    def get_access_token(self):
        """
        get access token
        Returns:

        """
        return self.access_token

    def get_host_ip(self):
        """
        get host ip
        Returns:

        """
        return self.host_ip


class UploadPackageRequest:
    """
    上传请求体封装
    """
    access_token = None
    host_ip = None
    app_package_id = None
    tenant_id = None

    def __init__(self, request_iterator):
        task_id = utils.gen_uuid()
        self._tmp_package_dir = _APP_TASK_PATH + '/' + task_id
        utils.create_dir(self._tmp_package_dir)
        self.tmp_package_file_path = self._tmp_package_dir + '/package.zip'
        with open(self.tmp_package_file_path, 'ab') as file:
            for request in request_iterator:
                if request.accessToken:
                    self.access_token = request.accessToken
                elif request.appPackageId:
                    self.app_package_id = request.appPackageId
                elif request.hostIp:
                    self.host_ip = request.hostIp
                elif request.tenantId:
                    self.tenant_id = request.tenantId
                elif request.package:
                    file.write(request.package)

    def delete_tmp(self):
        """
        删除临时文件
        """
        utils.delete_dir(self._tmp_package_dir)

    def get_tmp_file_path(self):
        """
        获取临时文件目录
        """
        return self.tmp_package_file_path


_APP_PACKAGE_PATH_FORMATTER = '{base_dir}/package/{host_ip}/{app_package_id}'


class InstantiateRequest:
    """
    实例化请求体封装
    """
    access_token = None
    host_ip = None
    app_instance_id = None
    app_package_id = None
    app_package_path = None
    parameters = None
    ak_sk_lcm_gen = None

    def __init__(self, request):
        self.access_token = request.accessToken
        self.app_instance_id = request.appInstanceId
        self.host_ip = request.hostIp
        self.app_package_id = request.appPackageId
        self.app_package_path = _APP_PACKAGE_PATH_FORMATTER\
            .format(base_dir=config.base_dir, host_ip=request.hostIp,
                    app_package_id=request.appPackageId)

        self.parameters = request.parameters
        self.ak_sk_lcm_gen = request.akSkLcmGen

    def get_app_package_path(self):
        """
        get app package path
        Returns:

        """
        return self.app_package_path

    def get_host_ip(self):
        """
        get host ip
        Returns:

        """
        return self.host_ip


class UploadCfgRequest:
    """
    配置上传请求体封装
    """
    access_token = None
    host_ip = None
    config_file = None

    def __init__(self, request_iterator):
        for request in request_iterator:
            if request.accessToken:
                self.access_token = request.accessToken
            elif request.hostIp:
                self.host_ip = request.hostIp
            elif request.configFile:
                self.config_file = request.configFile

    def get_config_file(self):
        """
        get config file
        Returns:

        """
        return self.config_file

    def get_host_ip(self):
        """
        get host ip
        Returns:

        """
        return self.host_ip


class AppInsMapper(db.Entity):
    """
    t_app_instance表映射
    """
    _table_ = 't_app_instance'
    app_instance_id = PrimaryKey(str, max_len=64)
    host_ip = Required(str, max_len=15)
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


class VmImageInfoMapper(db.Entity):
    """
    t_vm_image_info表映射
    """
    _table_ = 't_vm_image_info'
    image_id = Required(str, max_len=64)
    host_ip = Required(str, max_len=15)
    image_name = Required(str, max_len=64)
    status = Required(str, max_len=20)
    tenant_id = Optional(str, max_len=64)
    app_package_id = Optional(str, max_len=64)
    image_size = Optional(int, size=64, nullable=True)
    checksum = Optional(str, max_len=64, nullable=True)
    compress_task_id = Optional(str, max_len=64, nullable=True)

    def get_table_name(self):
        """
        get table name
        Returns:

        """
        return self._table_

    @classmethod
    def find_many(cls, app_package_id, host_ip):
        """
        根据查询条件查询多个实例对象
        :param app_package_id: 查询条件
        :param host_ip:
        :return:
        """
        return select(x for x in cls if x.app_package_id == app_package_id and x.host_ip == host_ip)


db.generate_mapping(create_tables=True)
