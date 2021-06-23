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
from pathlib import Path

import jwt

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
    create_dir(target)
    with zipfile.ZipFile(file) as zip_file:
        namelist = zip_file.namelist()
        for file in namelist:
            zip_file.extract(file, target)


def validate_access_token(access_token):
    """
    校验token
    """
    if access_token is None:
        LOG.info('accessToken required')
        return False
    try:
        payload = jwt.decode(access_token, jwt_public_key, algorithms=['RS256'])
        if 'authorities' not in payload:
            LOG.info('Invalid token A')
            return False
        if 'userId' not in payload:
            LOG.info('Invalid token UI')
            return False
        if 'user_name' not in payload:
            LOG.info('Invalid token UN')
            return False
    except jwt.PyJWTError as exception:
        LOG.error(exception, exc_info=True)
        # todo change to False
        return True
    return True


def validate_ipv4_address(host_ip):
    """
    验证ipv4格式
    """
    if host_ip is None:
        LOG.info('hostIp required')
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
        LOG.info('param require')
        return False
    pattern = re.compile(_UUID_PATTERN)
    return pattern.match(param)
