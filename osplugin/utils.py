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

import jwt
from jwt import DecodeError

from config import jwt_public_key
from core.log import logger

FAILURE = 'Failure'
SUCCESS = 'Success'

INSTANTIATING = 'Instantiating'
INSTANTIATED = 'Instantiated'
TERMINATED = 'Terminated'
TERMINATING = 'Terminating'

LOG = logger


def create_dir(path):
    try:
        os.makedirs(path)
    except OSError:
        LOG.debug('文件夹已存在')
    except Exception as e:
        LOG.error(e, exc_info=True)
        return False
    return True


def delete_dir(path):
    for i in os.listdir(path):
        file_data = path + '/' + i
        if os.path.isfile(file_data):
            os.remove(file_data)
        else:
            delete_dir(file_data)
    os.rmdir(path)


def validate_access_token(access_token):
    if not access_token:
        LOG.info('accessToken required')
        return False
    try:
        payload = jwt.decode(access_token, jwt_public_key, algorithms=['RS256'])
        if not payload['authorities']:
            LOG.info('Invalid token A')
            return False
        if not payload['userId']:
            LOG.info('Invalid token UI')
            return False
        if not payload['user_name']:
            LOG.info('Invalid token UN')
            return False
    except DecodeError as e:
        LOG.error(e, exc_info=True)
        return False
    return True


def validate_ipv4_address(host_ip):
    if not host_ip:
        LOG.info('hostIp required')
        return False
    p = re.compile('^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.)' +
                   '{3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    if p.match(host_ip):
        return True
    else:
        return False


def gen_uuid():
    return ''.join(str(uuid.uuid4()).split('-'))


def validate_uuid(param):
    if not param:
        LOG.info('param require')
        return False
    p = re.compile('^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
    if p.match(param):
        return True
    else:
        return False
