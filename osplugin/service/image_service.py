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
from io import BytesIO

from glanceclient.exc import HTTPException
from pony.orm import commit, db_session

import config
import utils
from core.log import logger
from core.models import VmImageInfoMapper
from core.openstack_utils import create_glance_client
from internal.resourcemanager import resourcemanager_pb2_grpc
from internal.resourcemanager.resourcemanager_pb2 import CreateVmImageResponse, QueryVmImageResponse, \
    DownloadVmImageResponse, DeleteVmImageResponse, UploadVmImageResponse, ImportVmImageResponse

from task.image_task import start_check_image_status, add_import_image_task

LOG = logger


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


class ImageService(resourcemanager_pb2_grpc.VmImageMangerServicer):
    """
    ImageService
    Author: cuijch

    """

    @db_session
    def createVmImage(self, request, context):
        """
        创建镜像信息记录
        """
        LOG.info("receive create vm image msg...")
        resp = CreateVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = utils.validate_input_params(request)

        metadata = dict(request.image.properties)
        metadata['name'] = request.image.name
        metadata['container_format'] = request.image.containerFormat
        metadata['disk_format'] = request.image.diskFormat
        metadata['min_ram'] = request.image.minRam
        metadata['min_disk'] = request.image.minDisk

        glance = create_glance_client(host_ip, request.tenantId)

        try:
            image = glance.images.create(**metadata)
        except HTTPException as http_exception:
            resp.response = json.dumps({
                'data': None,
                'retCode': http_exception.code,
                'message': http_exception.details
            })
            return resp
        VmImageInfoMapper(
            image_id=image['id'],
            image_name=image['name'],
            status=image['status'],
            host_ip=host_ip,
            tenant_id=request.tenantId
        )
        commit()

        resp.response = json.dumps({'data': {'imageId': image['id']}, 'retCode': 200, 'message': 'Create Image Success'})
        LOG.info('create image record created')
        return resp

    @db_session
    def queryVmImage(self, request, context):
        """
        查询镜像信息
        """
        LOG.info("receive query vm image msg...")
        resp = QueryVmImageResponse(response=utils.FAILURE_JSON)
        host_ip = utils.validate_input_params(request)

        resp_data = {
            'retCode': 200,
            'message': 'Query Images Success'
        }
        if not request.imageId:
            resp_data['data'] = []
            glance = create_glance_client(host_ip, request.tenantId)
            images = glance.images.list()
            for image in images:
                resp_data['data'].append({
                    'imageId': image['id'],
                    'imageName': image['name'],
                    'status': image['status'],
                    'size': image['size'],
                    'checksum': image['checksum'],
                    'visibility': image['visibility'],
                    'protected': image['protected']
                })
            resp.response = json.dumps(resp_data)
            return resp

        image_info = VmImageInfoMapper.get(image_id=request.imageId, host_ip=host_ip)

        if image_info is None:
            LOG.error('image %s not found', request.imageId)
            return resp

        LOG.info("query image success")

        res_dir = {
            'imageId': image_info.image_id,
            'imageName': image_info.image_name,
            'status': image_info.status,
            'size': image_info.image_size,
            'checksum': image_info.checksum,
            'compressTaskStatus': image_info.compress_task_status,
            'resourceUrl': image_info.remote_url
        }

        resp.response = json.dumps({'message': None, 'retCode': 200, 'data': res_dir})
        return resp

    @db_session
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
        image_db = VmImageInfoMapper.get(image_id=request.imageId, tenant_id=request.tenantId, host_ip=host_ip)
        if image_db is not None:
            image_db.delete()
            commit()
        resp_data = {
            'data': None,
            'retCode': 200,
            'message': 'Delete Image Success'
        }
        resp.status = json.dumps(resp_data)

        LOG.info("delete image %s success", request.imageId)
        return resp

    def downloadVmImage(self, request, context):
        """
        下载镜像
        """
        LOG.info("receive download vm image msg...")

        host_ip = utils.validate_input_params(request)
        if not host_ip:
            yield DownloadVmImageResponse(content=b'{"retCode":400,"message":"required param host_ip"}')
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
        status = json.dumps({
            'data': None,
            'retCode': 500,
            'message': 'Upload Image Failure'
        })
        resp = UploadVmImageResponse(status)

        access_token = next(request_iterator).accessToken
        host_ip = next(request_iterator).hostIp
        tenant_id = next(request_iterator).tenantId
        image_id = next(request_iterator).imageId

        if not utils.validate_access_token(access_token):
            LOG.error('accessToken not valid')
            return resp
        if not utils.validate_ipv4_address(host_ip):
            LOG.error('hostIp not match ipv4')
            return resp

        start_check_image_status(image_id, host_ip)

        glance = create_glance_client(host_ip, tenant_id)

        glance.images.upload(image_id=image_id, image_data=utils.StreamReader(request_iterator))

        LOG.info("upload finished")

        resp.status = json.dumps({
            'data': None,
            'retCode': 0,
            'message': 'Upload Image Success'
        })
        return resp

    def importVmImage(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info("received importVmImage message")
        resp = ImportVmImageResponse(status=utils.FAILURE)
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return resp

        add_import_image_task(request.imageId, host_ip, request.resourceUri)

        LOG.info('success add import image task')
        status = json.dumps({
            'data': None,
            'retCode': 0,
            'message': 'Import Image Success'
        })
        return ImportVmImageResponse(status)
