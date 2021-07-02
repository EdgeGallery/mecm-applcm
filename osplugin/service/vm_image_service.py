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
from io import BytesIO

from novaclient.exceptions import NotFound
from pony.orm import db_session, commit

import config
import utils
from core.exceptions import ParamNotValid
from core.log import logger
from core.models import VmImageInfoMapper
from core.openstack_utils import create_glance_client
from core.openstack_utils import create_nova_client
from internal.lcmservice import lcmservice_pb2_grpc
from internal.lcmservice.lcmservice_pb2 import CreateVmImageResponse, QueryVmImageResponse, \
    DownloadVmImageResponse, DeleteVmImageResponse
from task.image_task import start_check_image_status

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


class VmImageService(lcmservice_pb2_grpc.VmImageServicer):
    """
    VmImageService
    Author: wangy1

    """

    @db_session
    def createVmImage(self, request, context):
        """
        创建虚拟机快照
        """
        LOG.info("receive create vm image msg...")
        resp = CreateVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = validate_input_params_for_upload_cfg(request)
        if host_ip is None:
            LOG.info('hostIp not match ipv4')
            return resp
        if request.vmId is None or request.vmId == '':
            LOG.info("vmId is required")
            return resp

        try:
            nova_client = create_nova_client(host_ip)
            vm_info = nova_client.servers.get(request.vmId)
            LOG.info('vm %s: status: %s', vm_info['id'], vm_info['status'])
            image_name = get_image_name(vm_info['name'])
            image_id = nova_client.servers.create_image(request.vmId, image_name)
        except Exception as exception:
            LOG.error(exception, exc_info=True)
            return resp

        VmImageInfoMapper(image_id=image_id,
                          image_name=image_name,
                          status=utils.QUEUED,
                          host_ip=host_ip)
        commit()
        start_check_image_status(image_id, host_ip)
        resp.response = json.dumps({'imageId': image_id})
        LOG.info('create image record created, fetching image data')
        return resp

    @db_session
    def queryVmImage(self, request, context):
        """
        查询镜像信息
        """
        LOG.info("receive query vm image msg...")
        resp = QueryVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            LOG.info('hostIp not match ipv4')
            return resp
        vm_image_info = VmImageInfoMapper.get(image_id=request.imageId, host_ip=host_ip)
        if vm_image_info is None:
            LOG.info("image not found! image_id: %s", request.imageId)
            return resp

        res_dir = {
            "imageId": vm_image_info.image_id,
            "imageName": vm_image_info.image_name,
            "status": vm_image_info.status
        }
        if vm_image_info.status == utils.ACTIVE:
            res_dir['checksum'] = vm_image_info.checksum
            res_dir['sumChunkNum'] = get_chunk_num(
                size=vm_image_info.image_size,
                chunk_size=int(config.chunk_size))
            res_dir['chunkSize'] = config.chunk_size
        resp.response = json.dumps(res_dir)
        LOG.info("query image success")
        return resp

    @db_session
    def deleteVmImage(self, request, context):
        """
        删除镜像
        """
        LOG.info("receive delete vm image msg...")
        resp = DeleteVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = validate_input_params_for_upload_cfg(request)
        if host_ip is None:
            LOG.info('hostIp not match ipv4')
            return resp
        vm_info = VmImageInfoMapper.get(image_id=request.imageId, host_ip=host_ip)
        if vm_info is None:
            LOG.info("image not found! image_id: %s", request.imageId)
            return resp
        glance_client = create_glance_client(host_ip)
        try:
            glance_client.images.delete(request.imageId)
        except Exception as exception:
            LOG.error(exception, exc_info=True)
            return resp
        vm_info.delete()
        commit()
        resp.response = '{"code": 200, "msg": "Ok"}'
        LOG.info(f"delete image {request.imageId} success")
        return resp

    def downloadVmImage(self, request, context):
        """
        下载镜像
        """
        LOG.info("receive download vm image msg...")
        LOG.debug("download image chunk %s starting...", request.chunkNum)

        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            LOG.info('hostIp not match ipv4')
            raise ParamNotValid("host ip is null...")
        glance_client = create_glance_client(host_ip)

        iterable = glance_client.images.data(image_id=request.imageId)

        buf = BytesIO()
        buf_size = config.chunk_size
        send_size = 0
        for body in iterable:
            buf.write(body)
            if buf.tell() >= buf_size:
                yield DownloadVmImageResponse(content=buf.getvalue())
                send_size += buf.tell()
                LOG.debug('%s bytes send', send_size)
                buf.close()
                buf = BytesIO()

        if buf.tell() > 0:
            yield DownloadVmImageResponse(content=buf.getvalue())
            send_size += buf.tell()
            LOG.debug('all bytes send, size %s', send_size)
        buf.close()
        LOG.debug("finished download image")
        LOG.info('download image success')
