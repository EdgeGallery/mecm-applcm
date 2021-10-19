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
import json
import time
from pony.orm import db_session, commit

import requests
import utils
from config import image_push_url, base_dir
from core.log import logger
from core.models import VmImageInfoMapper
from core.openstack_utils import create_glance_client
from task import upload_thread_pool, check_thread_pool, download_thread_pool
from requests_toolbelt import MultipartEncoder

LOG = logger


def start_check_image_status(image_id, host_ip):
    """
    新增检查镜像状态任务
    Args:
        image_id: 镜像ID
        host_ip:

    Returns:

    """
    check_thread_pool.submit(do_check_image_status, image_id, host_ip)


@db_session
def create_image_record(sw_image, app_package_id, host_ip, tenant_id):
    """
    创建镜像记录
    Args:
        sw_image:
        app_package_id:
        host_ip:
        tenant_id:

    Returns: 镜像ID

    """
    glance = create_glance_client(host_ip, tenant_id)
    image = glance.images.create(name=sw_image.name,
                                 container_format=sw_image.container_format,
                                 min_ram=sw_image.min_ram,
                                 min_disk=sw_image.min_disk,
                                 architecture=sw_image.architecture,
                                 hw_disk_bus=sw_image.hw_disk_bus,
                                 file_format=sw_image.disk_format,
                                 __os_version=sw_image.operating_system,
                                 __quick_start='False',
                                 __os_type=sw_image.supported_virtualization_environment,
                                 cloudinit='True',
                                 virtual_env_type='KVM',
                                 hw_watchdog_action='none',
                                 disk_format=sw_image.disk_format)
    VmImageInfoMapper(
        image_id=image['id'],
        image_name=sw_image.name,
        status=image['status'],
        app_package_id=app_package_id,
        host_ip=host_ip,
        tenant_id=tenant_id
    )
    commit()
    return image['id']


def add_upload_image_task(image_id, host_ip, file_path):
    """
    创建镜像上传任务
    Args:
        image_id:
        host_ip:
        file_path:

    Returns:

    """
    future = upload_thread_pool.submit(do_upload_image, image_id, host_ip, file_path)
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
    upload_thread_pool.submit(do_import_image, image_id, host_ip, uri)
    start_check_image_status(image_id, host_ip)


def add_download_then_compress_image_task(image_id, host_ip):
    """
    启动镜像下载任务
    Args:
        image_id: 镜像id
        host_ip: 虚拟化基础

    Returns:

    """
    download_thread_pool.submit(do_download_then_compress_image, image_id, host_ip)


def add_check_compress_image_task(image_id, host_ip):
    """
    开始定时检查compress状态
    Args:
        image_id:
        host_ip:

    Returns:

    """
    check_thread_pool.submit(do_check_compress_status, image_id, host_ip)


def add_push_image_task(image_id, host_ip):
    """
    异步推送镜像到developer
    Args:
        image_id:
        host_ip:

    Returns:

    """
    upload_thread_pool.submit(do_push_image, image_id, host_ip)


@db_session
def do_check_image_status(image_id, host_ip):
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
        glance = create_glance_client(host_ip, image_info.tenant_id)
        image = glance.images.get(image_id)
    except Exception as exception:
        LOG.error(exception, exc_info=True)
        return
    if image is None:
        image_info.delete()
        commit()
        return

    LOG.debug('now image status is %s', image['status'])
    if image['status'] == utils.ACTIVE:
        image_info.checksum = image['checksum']
        image_info.image_size = image['size']
        if image_info.app_package_id is None or image_info.app_package_id == '':
            image_info.status = utils.DOWNLOADING
            commit()
            LOG.debug('download created image to local')
            add_download_then_compress_image_task(image_id, host_ip)
        else:
            LOG.debug('image in package %s', image_info.app_package_id)
            image_info.status = utils.ACTIVE
            commit()
    elif image['status'] == utils.KILLED:
        image_info.status = utils.KILLED
        commit()
    else:
        start_check_image_status(image_id, host_ip)


@db_session
def do_upload_image(image_id, host_ip, file_path):
    """
    上传本地镜像到openstack
    Args:
        image_id:
        host_ip:
        file_path:

    Returns:

    """
    image_info = VmImageInfoMapper.get(image_id=image_id, host_ip=host_ip)
    glance = create_glance_client(host_ip, image_info.tenant_id)
    try:
        with open(file_path, 'rb') as image_data:
            LOG.debug('start upload image %s', image_id)
            glance.images.upload(image_id, image_data=image_data)
            LOG.debug('finish upload image %s', image_id)
    except Exception as exception:
        image_info.status = utils.KILLED
        commit()
        LOG.error(exception, exc_info=True)


@db_session
def do_import_image(image_id, host_ip, uri):
    """
    上传远端镜像到openstack
    """
    image_info = VmImageInfoMapper.get(image_id=image_id, host_ip=host_ip)
    glance = create_glance_client(host_ip, image_info.tenant_id)
    try:
        LOG.debug('start upload image %s', image_id)
        with requests.get(uri, stream=True) as resp_stream:
            glance.images.upload(image_id=image_id, image_data=resp_stream.raw)
        LOG.debug('finished upload image %s', image_id)
    except Exception as exception:
        image_info.status = utils.KILLED
        commit()
        LOG.error(exception, exc_info=True)


@db_session
def do_download_then_compress_image(image_id, host_ip):
    """
    下载openstack镜像到本地，然后转换格式为qcow2
    Args:
        image_id:
        host_ip:

    Returns:

    """
    image_info = VmImageInfoMapper.get(image_id=image_id, host_ip=host_ip)
    if image_info is None or image_info.status != utils.DOWNLOADING:
        return

    glance_client = create_glance_client(host_ip=host_ip, tenant_id=image_info.tenant_id)
    try:
        logger.debug('start download image: %s from openstack', image_id)
        download_dir = f'{base_dir}/vmImage/{host_ip}'
        utils.create_dir(download_dir)
        with open(f'{download_dir}/{image_id}.img', 'wb') as image_file:
            for body in glance_client.images.data(image_id=image_id):
                image_file.write(body)
        logger.debug('finished download image: %s from openstack', image_id)

        body = {
            'inputImageName': f'{host_ip}/{image_id}.img',
            'outputImageName': f'{host_ip}/{image_id}.qcow2'
        }

        headers = {
            'content-type': 'application/json'
        }

        response = requests.post(
            url='http://localhost:5000/api/v1/vmimage/compress',
            data=json.dumps(body),
            headers=headers)
        data = response.json()
        if response.status_code != 200:
            logger.error('compress image failed, cause: %s', data['msg'])
            image_info.status = utils.KILLED
            commit()
            utils.delete_dir(f'{base_dir}/vmImage/{host_ip}/{image_id}.img')
            return

        image_info.status = utils.COMPRESSING
        image_info.compress_task_id = data['requestId']
        commit()
    except Exception as exception:
        logger.error(exception, exc_info=True)
        image_info.status = utils.KILLED
        commit()
        utils.delete_dir(f'{base_dir}/vmImage/{host_ip}/{image_id}.img')
        return

    add_check_compress_image_task(image_id, host_ip)


@db_session
def do_check_compress_status(image_id, host_ip):
    """
    检查compress状态
    Args:
        image_id:
        host_ip:

    Returns:

    """
    time.sleep(5)

    image_info = VmImageInfoMapper.get(image_id=image_id, host_ip=host_ip)
    if image_info is None or image_info.status != utils.COMPRESSING:
        return

    try:
        response = requests.get(
            f'http://localhost:5000/api/v1/vmimage/compress/{image_info.compress_task_id}')
        data = response.json()
        if response.status_code != 200:
            logger.error('check compress progress failed, cause: %s 。skip', data['msg'])
            return

        if data['status'] == 0:
            logger.debug('image: %s compress finished, start push', image_id)
            image_info.status = utils.PUSHING
            add_push_image_task(image_id, host_ip)
        elif data['status'] == 1:
            logger.debug('image: %s are compressing, rate %f', image_id, data['rate'])
            add_check_compress_image_task(image_id, host_ip)
            return
        else:
            logger.debug('image: %s compress failed, cause %s', image_id, data['msg'])
            image_info.status = utils.KILLED
            utils.delete_dir(f'{base_dir}/vmImage/{host_ip}/{image_id}.qcow2')
        commit()
        utils.delete_dir(f'{base_dir}/vmImage/{host_ip}/{image_id}.img')
    except Exception as exception:
        logger.error(exception, exc_info=True)


@db_session
def do_push_image(image_id, host_ip):
    """
    调用接口推送镜像
    Args:
        image_id:
        host_ip:

    Returns:

    """
    image_info = VmImageInfoMapper.get(image_id=image_id, host_ip=host_ip)
    if image_info is None or image_info.status != utils.PUSHING:
        return
    try:
        data = MultipartEncoder({
            'file': (f'{image_id}.qcow2',
                     open(f'{base_dir}/vmImage/{host_ip}/{image_id}.qcow2', 'rb'),
                     'application/octet-stream'),
            'priority': '0',
            'userId': image_info.tenant_id
        })
        req_headers = {
            'Content-Type': data.content_type
        }
        logger.debug('start push image: %s to developer', image_id)
        response = requests.post(image_push_url, data=data, headers=req_headers)
        if response.status_code != 200:
            logger.error('developer response an error: %s', response.json())
            image_info.status = utils.KILLED
            commit()
            return

        response_data = response.json()
        image_info.compress_task_id = response_data['imageId']
        image_info.status = utils.ACTIVE
        commit()
    except Exception as exception:
        logger.error(exception, exc_info=True)
        image_info.status = utils.KILLED
        commit()
    finally:
        utils.delete_dir(f'{base_dir}/vmImage/{host_ip}/{image_id}.qcow2')
