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
import logging
import time

from pony.orm import db_session, commit

import config
import utils
from core.models import VmImageInfoMapper, AppInsMapper
from core.openstack_utils import create_glance_client
from core.openstack_utils import create_heat_client
from core.openstack_utils import create_nova_client
from internal.lcmservice import lcmservice_pb2_grpc
from internal.lcmservice.lcmservice_pb2 import CreateVmImageResponse, QueryVmImageResponse, \
    DownloadVmImageResponse, DeleteVmImageResponse


def get_image_name(name):
    """
    get_image_name
    Args:
        name: name
    Returns:
        image_name
    """
    return name + "-" + time.strftime("%Y%m%d%H%M", time.localtime())


def get_chunk_num(size, chunk_size=1024):
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


class VmImageService(lcmservice_pb2_grpc.VmImageServicer):
    """
    VmImageService
    Author: wangy1

    """

    @db_session
    def createVmImage(self, request, context):
        res = CreateVmImageResponse(response=utils.FAILURE)
        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            return res
        app_ins_mapper = AppInsMapper.get(app_instance_id=request.appInstanceId)
        if not app_ins_mapper:
            return
        heat = create_heat_client(app_ins_mapper.host_ip)
        stack_resp = heat.stacks.get(app_ins_mapper.stack_id)
        if stack_resp is None and stack_resp.status == utils.TERMINATED:
            app_ins_mapper.delete()
        nova_client = create_nova_client(host_ip)
        vm_info = nova_client.servers.get(request.vmId)
        logging.info('vm %s: status: %s', vm_info.id, vm_info.status)
        image_name = get_image_name(vm_info.name)
        image_id = nova_client.servers.create_image(request.vmId, image_name)
        glance_client = create_glance_client(host_ip)
        image_info = glance_client.images.get(image_id)

        # 虚机从卷启动时，创建镜像后镜像大小为0 需要从卷上传打包成镜像才可以下载, 调用update_to_image 需要删除虚机
        # block_device_mapping = json.loads(image_info.block_device_mapping)
        # cinder_client = create_cinder_client(host_ip)
        # snap = cinder_client.volume_snapshots.get(block_device_mapping[0]["snapshot_id"])
        # image = cinder_client.volumes.upload_to_image(snap.volume_id,
        #                                               image_name="test--1", disk_format="qcow2",
        #                                               container_format="bare", force=False)

        VmImageInfoMapper(image_id=image_id,
                          image_name=image_name,
                          image_size=image_info.size,
                          vm_id=request.vmId,
                          app_instance_id=request.appInstanceId,
                          host_ip=request.hostIp)
        commit()
        res.response = image_id
        return res

    @db_session
    def queryVmImage(self, request, context):
        res = QueryVmImageResponse(response=utils.FAILURE)
        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            return res
        vm_info = VmImageInfoMapper.get(image_id=request.imageId)
        if not vm_info:
            logging.info("image not found! image_id: %s", request.imageId)
            return res
        glance_client = create_glance_client(host_ip)
        image_info = glance_client.images.get(request.imageId)
        logging.info("openstack image %s status: %s", image_info.id, image_info.status)
        res.response = json.dumps({
            "imageId": vm_info.image_id,
            "imageName": vm_info.image_name,
            "appInstanceId": vm_info.app_instance_id,
            "status": image_info.status,
            "sumChunkNum": get_chunk_num(vm_info.image_size),
            "chunkSize": config.chunk_size
        })
        return res

    @db_session
    def deleteVmImage(self, request, context):
        res = DeleteVmImageResponse(response=utils.FAILURE)
        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            return res
        vm_info = VmImageInfoMapper.get(image_id=request.imageId)
        if not vm_info:
            logging.info("image not found! image_id: %s", request.imageId)
            return res
        glance_client = create_glance_client(host_ip)
        image_res = glance_client.images.delete(request.imageId)
        vm_info.delete()
        commit()
        print(image_res)
        res.response = utils.SUCCESS
        return res

    @db_session
    def downloadVmImage(self, request, context):
        res = DownloadVmImageResponse(content=bytes(utils.FAILURE, encoding='utf8'))
        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            return res
        vm_info = VmImageInfoMapper.get(image_id=request.imageId)
        if not vm_info:
            logging.info("image not found! image_id: %s", request.imageId)
            return res
        glance_client = create_glance_client(host_ip)
        iterable_with_length, resp = \
            glance_client.images.download_chunk(request.chunkNum,
                                                vm_info.image_size,
                                                request.imageId, False,
                                                chunk_size=int(config.chunk_size))
        logging.debug("download image: image_size: %s, chunk_num: %s ,chunk_size: %s ",
                      vm_info.image_size,
                      request.chunkNum,
                      config.chunk_size)
        print(len(resp.content))

        res = DownloadVmImageResponse(content=resp.content)
        yield res
