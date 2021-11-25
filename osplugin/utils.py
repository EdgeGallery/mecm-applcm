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
import uuid
import zipfile
from io import IOBase
from pathlib import Path

import jwt
from jwt import PyJWTError

from config import jwt_public_key, base_dir
from core.log import logger

FAILURE = 'Failure'
SUCCESS = 'Success'
FAILURE_JSON = '{"code": 500}'

QUEUED = 'queued'
SAVING = 'saving'
DEACTIVATED = 'deactivated'
UPLOADING = 'uploading'
ACTIVE = 'active'
KILLED = 'killed'
DOWNLOADING = 'downloading'
COMPRESSING = 'compressing'
WAITING = 'waiting'
PUSHING = 'pushing'

UPLOADED = 'uploaded'
ERROR = 'error'

INSTANTIATING = 'Instantiating'
INSTANTIATED = 'Instantiated'
TERMINATED = 'Terminated'
TERMINATING = 'Terminating'

APP_PACKAGE_DIR = base_dir + '/package'

RC_FILE_DIR = base_dir + '/config'

LOG = logger

_IPV4_PATTERN = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}' \
                '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

_UUID_PATTERN = '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'

APP_INS_ERR_MDG = 'appInstanceId is required'


def create_dir(path):
    """
    创建目录
    """
    try:
        os.makedirs(path)
    except OSError:
        LOG.debug('文件夹已存在')
    except Exception as exception:
        LOG.error(exception, exc_info=True)
        return False
    return True


def exists_path(path):
    """
    判断目录是否存在
    """
    file = Path(path)
    return file.exists()


def delete_dir(path):
    """
    删除目录
    """
    if not exists_path(path):
        return
    if os.path.isfile(path):
        os.remove(path)
        return
    for i in os.listdir(path):
        file_data = path + '/' + i
        if os.path.isfile(file_data):
            os.remove(file_data)
        else:
            delete_dir(file_data)
    os.rmdir(path)


def unzip(file, target):
    """
    解压缩
    Args:
        file:
        target:

    Returns:

    """
    create_dir(target)
    with zipfile.ZipFile(file) as zip_file:
        namelist = zip_file.namelist()
        for _file in namelist:
            zip_file.extract(_file, target)


def validate_access_token(access_token):
    """
    校验token
    """
    if access_token is None:
        return True
    try:
        payload = jwt.decode(access_token, jwt_public_key, algorithms=['RS256'])
        if 'authorities' not in payload:
            return False
        if 'userId' not in payload:
            return False
        if 'user_name' not in payload:
            return False
    except PyJWTError:
        LOG.debug("skip accessToken check")
        # test, change false future
        return True
    return True


def validate_ipv4_address(host_ip):
    """
    验证ipv4格式
    """
    if host_ip is None:
        return False
    pattern = re.compile(_IPV4_PATTERN)
    return pattern.match(host_ip)


def gen_uuid():
    """
    生产uuid
    """
    return ''.join(str(uuid.uuid4()).split('-'))


def validate_uuid(param):
    """
    校验uuid格式
    """
    if param is None:
        LOG.error('param require')
        return False
    pattern = re.compile(_UUID_PATTERN)
    return pattern.match(param)


def validate_input_params(param):
    """
    校验通用参数,host_ip和token，返回host_ip
    Args:
        param: 包含hostIp和accessToken
    Returns:
        host_ip
    """
    access_token = param.accessToken
    host_ip = param.hostIp
    if not validate_access_token(access_token):
        LOG.error('accessToken not valid')
        return None
    if not validate_ipv4_address(host_ip):
        LOG.error('hostIp not match ipv4')
        return None
    if param.tenantId is None:
        LOG.error('tenantId is required')
        return None
    return host_ip


class StreamReader(IOBase):
    def __init__(self, request_iter):
        self.data_iter = request_iter
        self.is_end = False

    def read(self, size) -> bytes:
        if self.is_end:
            return bytes()
        request = next(self.data_iter, None)
        if request is None:
            self.is_end = True
            return bytes()
        return request.content

    def fileno(self) -> int:
        raise IOError('not a file')

    def isatty(self) -> bool:
        return False

    def readable(self) -> bool:
        return True

    def seek(self, __offset: int, __whence: int = ...) -> int:
        raise IOError('can not seek!')

    def seekable(self) -> bool:
        return False
