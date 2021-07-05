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
import time

import urllib3
from pony.orm import db_session, commit

import utils
from core.log import logger
from core.models import VmImageInfoMapper
from core.openstack_utils import create_glance_client
from task import upload_thread_pool, check_thread_pool


LOG = logger

http = urllib3.PoolManager()


def start_check_image_status(image_id, host_ip):
    """
    新增检查镜像状态任务
    Args:
        image_id: 镜像ID
        host_ip:

    Returns:

    """
    check_thread_pool.submit(_check_image_status, image_id, host_ip)


@db_session
def _check_image_status(image_id, host_ip):
    """
    检查镜像状态
    Args:
        image_id: 镜像ID
        host_ip:

    Returns:

    """
    time.sleep(5)
    try:
        image_info = VmImageInfoMapper.get(image_id=image_id, host_ip=host_ip)
        if image_info is None:
            return
        if image_info.status == utils.KILLED:
            return
        glance = create_glance_client(host_ip)
        image = glance.images.get(image_id)
    except Exception as exception:
        LOG.error(exception, exc_info=True)
        return
    if image is None:
        image_info.delete()
        commit()
        return
    image_info.status = image['status']
    image_info.checksum = image['checksum']
    image_info.image_size = image['size']
    commit()
    LOG.debug('now image status is %s' % image_info.status)
    if image_info.status != utils.ACTIVE:
        start_check_image_status(image_id, host_ip)


@db_session
def create_image_record(sw_image, app_package_id, host_ip):
    """
    创建镜像记录
    Args:
        sw_image:
        app_package_id:
        host_ip:

    Returns: 镜像ID

    """
    glance = create_glance_client(host_ip)
    image = glance.images.create(name=sw_image.name,
                                 container_format=sw_image.container_format,
                                 min_ram=sw_image.min_ram,
                                 min_disk=sw_image.min_disk,
                                 architecture=sw_image.architecture,
                                 disk_format=sw_image.disk_format)
    VmImageInfoMapper(
        image_id=image['id'],
        image_name=sw_image.name,
        status=image['status'],
        app_package_id=app_package_id,
        host_ip=host_ip
    )
    commit()
    return image['id']


@db_session
def _do_upload_image(image_id, host_ip, file_path):
    """
    上传镜像
    Args:
        image_id:
        host_ip:
        file_path:

    Returns:

    """
    glance = create_glance_client(host_ip)
    try:
        with open(file_path, 'rb') as image_data:
            LOG.debug('start upload image %s' % image_id)
            glance.images.upload(image_id, image_data=image_data)
            LOG.debug('finish upload image %s' % image_id)
    except Exception as exception:
        image = VmImageInfoMapper.get(image_id=image_id, host_ip=host_ip)
        image.status = utils.KILLED
        commit()
        LOG.error(exception, exc_info=True)


def add_upload_image_task(image_id, host_ip, file_path):
    """
    创建镜像上传任务
    Args:
        image_id:
        host_ip:
        file_path:

    Returns:

    """
    future = upload_thread_pool.submit(_do_upload_image, image_id, host_ip, file_path)
    start_check_image_status(image_id, host_ip)
    return future


def add_import_image_task(image_id, host_ip, uri):
    """
    添加加载远程镜像任务
    Args:
        image_id:
        host_ip:
        uri:

    Returns:

    """
    upload_thread_pool.submit(_import_image_by_python, image_id, host_ip, uri)
    start_check_image_status(image_id, host_ip)


@db_session
def _import_image_by_os_func(image_id, host_ip, uri):
    """
    使用Openstack自带功能上传远端镜像
    """
    glance = create_glance_client(host_ip)
    try:
        glance.images.image_import(image_id, method='web-download', uri=uri)
    except Exception as exception:
        image = VmImageInfoMapper.get(image_id=image_id, host_ip=host_ip)
        image.status = utils.KILLED
        commit()
        LOG.error(exception, exc_info=True)


@db_session
def _import_image_by_python(image_id, host_ip, uri):
    """
    本地上传远端镜像
    """
    glance = create_glance_client(host_ip)
    try:
        LOG.debug('open connection %s' % uri)
        resp_stream = http.request('GET', uri, preload_content=False)
        LOG.debug('start upload image %s' % image_id)
        glance.images.upload(image_id=image_id, image_data=resp_stream)
        LOG.debug('finished upload image %s' % image_id)
    except Exception as exception:
        image = VmImageInfoMapper.get(image_id=image_id, host_ip=host_ip)
        image.status = utils.KILLED
        commit()
        LOG.error(exception, exc_info=True)
