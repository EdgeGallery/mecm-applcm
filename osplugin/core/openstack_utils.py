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

# -*- coding: utf-8 -*-
"""

import re

from core.exceptions import OsConfigNotValid
from core.log import logger

from cinderclient.v3.client import Client as CinderClient
from gnocchiclient.v1.client import Client as GnocchiClient
from glanceclient.v2.client import Client as GlanceClient
from heatclient.v1.client import Client as HeatClient
from keystoneclient.v3.client import Client as KeystoneClient
from neutronclient.v2_0.client import Client as NeutronClient
from keystoneauth1 import identity, session
from novaclient import client as nova_client

import config
import utils

_RC_MAP = {}


def set_rc(host_ip, tenant_id):
    """
    缓存rc表
    """
    _RC_MAP[f'{host_ip}-{tenant_id}'] = RCFile(utils.RC_FILE_DIR + '/' + tenant_id + '/' + host_ip)


def del_rc(host_ip, tenant_id):
    """
    删除rc表
    """
    if f'{host_ip}-{tenant_id}' in _RC_MAP:
        _RC_MAP.pop(f'{host_ip}-{tenant_id}')


def get_rc(host_ip, tenant_id):
    """
    获取rc表
    """
    if f'{host_ip}-{tenant_id}' not in _RC_MAP:
        set_rc(host_ip, tenant_id)
    return _RC_MAP[f'{host_ip}-{tenant_id}']


def get_session(host_ip, tenant_id):
    """
    创建Openstack session
    """
    rc_data = get_rc(host_ip, tenant_id)
    auth = identity.Password(
        user_domain_name=rc_data.user_domain_name,
        username=rc_data.username,
        password=rc_data.password,
        project_domain_name=rc_data.project_domain_name,
        project_name=rc_data.project_name,
        auth_url=rc_data.auth_url
    )
    return session.Session(auth=auth, verify=config.server_ca_verify)


def create_heat_client(host_ip, tenant_id):
    """
    创建heat客户端
    """
    rc_data = get_rc(host_ip, tenant_id)
    return HeatClient(session=get_session(host_ip, tenant_id), endpoint_override=rc_data.heat_url)


def create_nova_client(host_ip, tenant_id):
    """
    创建nova客户端
    """
    rc_data = get_rc(host_ip, tenant_id)
    return nova_client.Client('2',
                              session=get_session(host_ip, tenant_id),
                              endpoint_override=rc_data.nova_url)


def create_glance_client(host_ip, tenant_id):
    """
    创建glance客户端
    """
    rc_data = get_rc(host_ip, tenant_id)
    return GlanceClient(session=get_session(host_ip, tenant_id), endpoint_override=rc_data.glance_url)


def create_keystone_client(host_ip, tenant_id):
    """
    创建keystone客户端
    Args:
        host_ip:
        tenant_id:

    Returns:

    """
    rc_data = get_rc(host_ip, tenant_id)
    return KeystoneClient(session=get_session(host_ip, tenant_id), endpoint_override=rc_data.auth_url)


def create_neutron_client(host_ip, tenant_id):
    """

    Args:
        host_ip:
        tenant_id:

    Returns:

    """
    rc_data = get_rc(host_ip, tenant_id)
    return NeutronClient(session=get_session(host_ip, tenant_id), endpoint_override=rc_data.neutron_url)


def create_gnocchi_client(host_ip, tenant_id):
    """

    Args:
        host_ip:
        tenant_id:

    Returns:

    """
    rc_data = get_rc(host_ip, tenant_id)
    adapter_options = None
    if rc_data.gnocchi_url:
        adapter_options = {'endpoint_override': rc_data.gnocchi_url}
    return GnocchiClient(session=get_session(host_ip, tenant_id), adapter_options=adapter_options)


def create_cinder_client(host_ip, tenant_id):
    rc_data = get_rc(host_ip, tenant_id)
    return CinderClient(session=get_session(host_ip, tenant_id), endpoint_override=rc_data.cinder_url)


def get_image_by_name_checksum(name, checksum, host_ip, tenant_id):
    """
    根据名称和校验和获取镜像
    Args:
        tenant_id: 租户id
        name: 名称
        checksum: 校验和
        host_ip:

    Returns: 镜像信息

    """
    glance = create_glance_client(host_ip, tenant_id)
    images = glance.images.list(filters={'name': name})
    for image in images:
        if image['checksum'] == checksum:
            return image
    return None


class RCFile:
    """
    rc文件解析类
    """
    _PATTERN = r'^export (.+)=(.+)$'

    user_domain_name = 'Default'
    project_domain_name = 'Default'
    username = None
    password = None
    project_name = None
    auth_url = None
    heat_url = None
    nova_url = None
    glance_url = None
    neutron_url = None
    gnocchi_url = None
    cinder_url = None

    def __init__(self, rc_path):
        try:
            with open(rc_path, 'r') as file:
                for line in file.readlines():
                    if line == '\n':
                        continue
                    match = re.match(self._PATTERN, line)
                    group1 = match.group(1)
                    group2 = match.group(2).replace('"', '')
                    if group1 == 'OS_AUTH_URL':
                        self.auth_url = group2
                    elif group1 == 'OS_USERNAME':
                        self.username = group2
                    elif group1 == 'OS_PASSWORD':
                        self.password = group2
                    elif group1 == 'OS_PROJECT_NAME':
                        self.project_name = group2
                    elif group1 == 'OS_PROJECT_DOMAIN_NAME':
                        self.project_domain_name = group2
                    elif group1 == 'OS_USER_DOMAIN_NAME':
                        self.user_domain_name = group2
                    elif group1 == 'HEAT_URL':
                        self.heat_url = group2
                    elif group1 == 'GLANCE_URL':
                        self.glance_url = group2
                    elif group1 == 'NOVA_URL':
                        self.nova_url = group2
                    elif group1 == 'CINDER_URL':
                        self.cinder_url = group2
                    elif group1 == 'NEUTRON_URL':
                        self.neutron_url = group2
                    elif group1 == 'GNOCCHI_URL':
                        self.gnocchi_url = group2
                    elif group1 == 'CINDER_URL':
                        self.cinder_url = group2
        except Exception as exception:
            logger.error(exception, exc_info=True)
            raise OsConfigNotValid()

    def get_auth_url(self):
        """
        get auth url
        Returns:

        """
        return self.auth_url

    def get_heat_url(self):
        """
        get heat url
        Returns:

        """
        return self.heat_url
