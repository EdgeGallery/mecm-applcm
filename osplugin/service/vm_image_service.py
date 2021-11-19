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

import requests
from pony.orm import commit

import config
import utils
from core.log import logger
from core.openstack_utils import create_glance_client
from internal.resourcemanager import resourcemanager_pb2_grpc
from internal.resourcemanager.resourcemanager_pb2 import CreateVmImageResponse, QueryVmImageResponse, \
    DownloadVmImageResponse, DeleteVmImageResponse, UploadVmImageResponse, ImportVmImageResponse
from task import upload_thread_pool

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


def import_image(image_id, host_ip, tenant_id, uri):
    glance = create_glance_client(host_ip, tenant_id)
    try:
        LOG.debug('start upload image %s', image_id)
        with requests.get(uri, stream=True) as resp_stream:
            glance.images.upload(image_id=image_id, image_data=resp_stream.raw)
        LOG.debug('finished upload image %s', image_id)
        return True
    except Exception as exception:
        LOG.error(exception, exc_info=True)
        return False


class VmImageService(resourcemanager_pb2_grpc.VmImageMangerServicer):
    """
    VmImageService
    Author: wangy1

    """

    def createVmImage(self, request, context):
        """
        创建镜像信息记录
        """
        LOG.info("receive create vm image msg...")
        resp = CreateVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = utils.validate_input_params(request)
        glance = create_glance_client(host_ip, request.tenantId)

        metadata = request.image.properties
        metadata['name'] = request.image.name
        metadata['container_format'] = request.image.containerFormat
        metadata['disk_format'] = request.image.diskFormat
        metadata['min_ram'] = request.image.minRam
        metadata['min_disk'] = request.image.minDisk

        image = glance.images.create(**metadata)

        resp.response = json.dumps({'imageId': image['id']})
        LOG.info('create image record created')
        return resp

    def queryVmImage(self, request, context):
        """
        查询镜像信息
        """
        LOG.info("receive query vm image msg...")
        resp = QueryVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = utils.validate_input_params(request)

        glance = create_glance_client(host_ip=host_ip, tenant_id=request.tenantId)

        if not request.imageId:
            resp.response = json.dumps(glance.images.list())
            return resp

        image_info = glance.images.get(image_id=request.imageId)

        res_dir = {
            "imageId": image_info.image_id,
            "imageName": image_info.image_name,
            "status": image_info.status
        }

        resp.response = json.dumps(res_dir)
        LOG.info("query image success")
        return resp

    def deleteVmImage(self, request, context):
        """
        删除镜像
        """
        LOG.info("receive delete vm image msg...")
        resp = DeleteVmImageResponse(status=utils.FAILURE)
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return resp
        glance_client = create_glance_client(host_ip, request.tenantId)
        try:
            glance_client.images.delete(request.imageId)
        except Exception as exception:
            LOG.error(exception, exc_info=True)
            return resp
        commit()
        resp.status = 'Success'
        LOG.info("delete image %s success", request.imageId)
        return resp

    def downloadVmImage(self, request, context):
        """
        下载镜像
        """
        LOG.info("receive download vm image msg...")
        LOG.debug("download image chunk %s starting...", request.chunkNum)

        host_ip = utils.validate_input_params(request)
        if not host_ip:
            yield DownloadVmImageResponse(content=b'{"code":400,"msg":"required param host_ip"}')
            return

        glance_client = create_glance_client(host_ip, request.tenantId)

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

    def uploadVmImage(self, request_iterator, context):
        """

        Args:
            request_iterator:
            context:

        Returns:

        """
        LOG.info("received uploadVmImage message")
        resp = UploadVmImageResponse(status='Failure')

        access_token = next(request_iterator)
        host_ip = next(request_iterator)
        tenant_id = next(request_iterator)
        image_id = next(request_iterator)

        if not utils.validate_access_token(access_token):
            LOG.error('accessToken not valid')
            return resp
        if not utils.validate_ipv4_address(host_ip):
            LOG.error('hostIp not match ipv4')
            return resp

        glance = create_glance_client(host_ip, tenant_id)

        glance.images.upload(image_id=image_id, image_data=utils.StreamReader(request_iterator))

        LOG.info("upload finished")
        resp.status = 'Success'
        return resp

    def importVmImage(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info("received importVmImage message")
        resp = ImportVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return resp

        upload_thread_pool.submit(import_image, request.imageId, host_ip, request.tenantId, request.resourceUri)
