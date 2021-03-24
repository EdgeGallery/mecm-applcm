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

import config
import utils
from core.exceptions import DownloadChunkException
from core.log import logger
from core.models import VmImageInfoMapper
from core.openstack_utils import create_glance_client
from core.openstack_utils import create_nova_client
from internal.lcmservice import lcmservice_pb2_grpc
from internal.lcmservice.lcmservice_pb2 import CreateVmImageResponse, QueryVmImageResponse, \
    DownloadVmImageResponse, DeleteVmImageResponse

LOG = logger


def get_image_name(name):
    """
    get_image_name
    Args:
        name: name
    Returns:
        image_name
    """
    return name + "-" + time.strftime("%Y%m%d%H%M", time.localtime())


def get_chunk_num(size, chunk_size=1048576):
    """
    get_chunk_num
    Args:
        size: name
        chunk_size
    Returns:
        chunk_num
    """
    if size % chunk_size == 0:
        return size // chunk_size
    return size // chunk_size + 1


def validate_input_params_for_upload_cfg(req):
    """
    validate_input_params_for_upload_cfg
    Args:
        req: req
    Returns:
        host_ip
    """
    access_token = req.accessToken
    host_ip = req.hostIp
    if not utils.validate_access_token(access_token):
        return None
    if not utils.validate_ipv4_address(host_ip):
        return None
    return host_ip


_IMAGE_INFO_TMP_ = {}


def _get_image_info(image_id, glance_client):
    if image_id in _IMAGE_INFO_TMP_:
        return _IMAGE_INFO_TMP_[image_id]
    image_info = glance_client.images.get(image_id)
    if image_info.status != 'active':
        LOG.error("image status %s", image_info.status)
        raise Exception("image status is not active...")
    _IMAGE_INFO_TMP_[image_id] = image_info
    return image_info


def _del_image_info(image_id):
    _IMAGE_INFO_TMP_.pop(image_id)


class VmImageService(lcmservice_pb2_grpc.VmImageServicer):
    """
    VmImageService
    Author: wangy1

    """

    @db_session
    def createVmImage(self, request, context):
        res = CreateVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            return res
        nova_client = create_nova_client(host_ip)
        vm_info = nova_client.servers.get(request.vmId)
        LOG.info('vm %s: status: %s', vm_info.id, vm_info.status)
        image_name = get_image_name(vm_info.name)
        try:
            image_id = nova_client.servers.create_image(request.vmId, image_name)
        except Exception as e:
            LOG.error(e, exc_info=True)
            return res
        # 虚机从卷启动时，创建镜像后镜像大小为0 需要从卷上传打包成镜像才可以下载, 调用update_to_image 需要删除虚机
        # block_device_mapping = json.loads(image_info.block_device_mapping)
        # cinder_client = create_cinder_client(host_ip)
        # snap = cinder_client.volume_snapshots.get(block_device_mapping[0]["snapshot_id"])
        # image = cinder_client.volumes.upload_to_image(snap.volume_id,
        #                                               image_name="test--1", disk_format="qcow2",
        #                                               container_format="bare", force=False)

        VmImageInfoMapper(image_id=image_id,
                          image_name=image_name,
                          image_size=0,
                          vm_id=request.vmId,
                          app_instance_id=request.appInstanceId,
                          host_ip=request.hostIp)
        commit()
        res.response = '{"imageId": "%s"}' % image_id
        return res

    @db_session
    def queryVmImage(self, request, context):
        res = QueryVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            return res
        vm_info = VmImageInfoMapper.get(image_id=request.imageId)
        if not vm_info:
            LOG.info("image not found! image_id: %s", request.imageId)
            return res
        glance_client = create_glance_client(host_ip)
        try:
            image_info = glance_client.images.get(request.imageId)
        except Exception as e:
            LOG.error(e, exc_info=True)
            return res
        LOG.info("openstack image %s status: %s", image_info.id, image_info.status)
        if image_info.status == 'active' and vm_info.image_size == 0:
            vm_info.image_size = image_info.size
            vm_info.status = image_info.status
            commit()
        res.response = json.dumps({
            "imageId": vm_info.image_id,
            "imageName": vm_info.image_name,
            "appInstanceId": vm_info.app_instance_id,
            "status": image_info.status,
            "sumChunkNum": get_chunk_num(size=image_info.size, chunk_size=int(config.chunk_size)),
            "chunkSize": config.chunk_size
        })

        return res

    @db_session
    def deleteVmImage(self, request, context):
        res = DeleteVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            return res
        vm_info = VmImageInfoMapper.get(image_id=request.imageId)
        if not vm_info:
            LOG.info("image not found! image_id: %s", request.imageId)
            return res
        glance_client = create_glance_client(host_ip)
        try:
            glance_client.images.delete(request.imageId)
        except Exception as e:
            LOG.error(e, exc_info=True)
            return res
        vm_info.delete()
        commit()
        res.response = '{"code": 200, "msg": "Ok"}'
        return res

    def downloadVmImage(self, request, context):
        LOG.debug("download image chunk %s starting...", request.chunkNum)

        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            raise Exception("host ip is null...")
        try:
            glance_client = create_glance_client(host_ip)
            image_info = _get_image_info(request.imageId, glance_client)
        except Exception as e:
            LOG.error(e, exc_info=True)
            raise e

        try:
            iterable_with_length, resp = \
                glance_client.images.download_chunk(chunk_num=request.chunkNum,
                                                    image_size=image_info.size,
                                                    image_id=request.imageId, do_checksum=False,
                                                    chunk_size=int(config.chunk_size))
            content = resp.content
        except DownloadChunkException as e:
            LOG.error(e, exc_info=True)
            raise e

        LOG.info("download image chunk %s end...", request.chunkNum)
        return iter([DownloadVmImageResponse(content=content)])
