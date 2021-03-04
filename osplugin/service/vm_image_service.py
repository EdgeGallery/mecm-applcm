# -*- coding: utf-8 -*-
from internal.lcmservice import lcmservice_pb2_grpc
from core.openstack_utils import create_nova_client
from core.openstack_utils import create_glance_client
from core.models import VmImageInfoMapper
from core.models import AppInsMapper
from internal.lcmservice.lcmservice_pb2 import CreateVmImageRequest, CreateVmImageResponse, QueryVmImageResponse, \
    DownloadVmImageResponse
import time
import utils
from pony.orm import db_session, commit
import json
import requests


def get_image_name(name):
    return name + "-" + time.strftime("%Y%m%d%H%M", time.localtime())


def get_chunk_num(size, chunk_size=1024):
    if size % chunk_size == 0:
        return size // chunk_size
    return size // chunk_size + 1


class VmImageService(lcmservice_pb2_grpc.VmImageServicer):

    @db_session
    def createVmImage(self, request, context):
        res = CreateVmImageResponse(response=utils.Failure)
        nova_client = create_nova_client(request.hostIp)
        # 使用 vm名称 创建镜像名称，接口响应较慢
        # vmInfo = nova_client.servers.get(request.vmId)

        image_name = get_image_name(request.vmId)
        image_id = nova_client.servers.create_image(request.vmId, image_name)

        glance_client = create_glance_client(request.hostIp)
        image_info = glance_client.images.get(image_id)
        print(image_info)
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
        res = QueryVmImageResponse(response=utils.Failure)
        vm_info = VmImageInfoMapper.get(image_id=request.imageId)
        print(type(vm_info))
        if not vm_info:
            return res
        glance_client = create_glance_client(request.hostIp)
        image_info = glance_client.images.get(request.imageId)
        print(image_info)
        res.response = json.dumps({
            "imageId": vm_info.image_id,
            "imageName": vm_info.image_name,
            "appInstanceId": vm_info.app_instance_id,
            "status": image_info.status,
            "sumChunkNum": get_chunk_num(vm_info.image_size),
            "chunkSize": 1024
        })
        return res

    @db_session
    def deleteVmImage(self, request, context):
        res = QueryVmImageResponse(response=utils.Failure)
        vm_info = VmImageInfoMapper.get(image_id=request.imageId)
        if not vm_info:
            return res
        print(request)
        glance_client = create_glance_client(vm_info.host_ip)
        image_res = glance_client.images.delete(request.imageId)
        vm_info.delete()
        commit()
        print(image_res)
        res.response = utils.Success
        return res

    def downloadVmImage(self, request, context):
        # res = DownloadVmImageResponse(content=utils.Failure)
        # vm_info = VmImageInfoMapper.get(image_id=request.imageId)
        # if not vm_info:
        #     return res
        glance_client = create_glance_client(request.hostIp)
        image_res = glance_client.images.data(request.imageId)
        glance_client.images.download_chunk(1, request.imageId, False, chunk_size=1)
        print(image_res)
        # stream = image_chunk_download(host_ip='10.10.9.75', image_id=request.imageId, chunk_num=request.chunkNum)
        return DownloadVmImageResponse(content=image_res)
