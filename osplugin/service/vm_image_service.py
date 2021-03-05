# -*- coding: utf-8 -*-
import json
import time

from pony.orm import db_session, commit
import logging
import config
import utils
from core.models import VmImageInfoMapper
from core.openstack_utils import create_glance_client
from core.openstack_utils import create_nova_client
from internal.lcmservice import lcmservice_pb2_grpc
from internal.lcmservice.lcmservice_pb2 import CreateVmImageResponse, QueryVmImageResponse, \
    DownloadVmImageResponse, DeleteVmImageResponse


def get_image_name(name):
    return name + "-" + time.strftime("%Y%m%d%H%M", time.localtime())


def get_chunk_num(size, chunk_size=1024):
    if size % chunk_size == 0:
        return size // chunk_size
    return size // chunk_size + 1


def validate_input_params_for_upload_cfg(req):
    access_token = req.accessToken
    host_ip = req.hostIp
    if not utils.validate_access_token(access_token):
        return None
    if not utils.validate_ipv4_address(host_ip):
        return None
    return host_ip


class VmImageService(lcmservice_pb2_grpc.VmImageServicer):

    @db_session
    def createVmImage(self, request, context):
        res = CreateVmImageResponse(response=utils.Failure)
        # host_ip = validate_input_params_for_upload_cfg(request)
        host_ip = request.hostIp
        if not host_ip:
            return res
        nova_client = create_nova_client(host_ip)
        # 使用 vm名称 创建镜像名称，接口响应较慢
        vmInfo = nova_client.servers.get(request.vmId)
        logging.info('vm %s: status: %s', vmInfo.id, vmInfo.status)
        image_name = get_image_name(request.vmId)
        image_id = nova_client.servers.create_image(request.vmId, image_name)

        glance_client = create_glance_client(host_ip)
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
        res = DeleteVmImageResponse(response=utils.Failure)
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
        res.response = utils.Success
        return res

    @db_session
    def downloadVmImage(self, request, context):
        res = DownloadVmImageResponse(content=bytes(utils.Failure, encoding='utf8'))
        host_ip = validate_input_params_for_upload_cfg(request)
        if not host_ip:
            return res
        vm_info = VmImageInfoMapper.get(image_id=request.imageId)
        if not vm_info:
            logging.info("image not found! image_id: %s", request.imageId)
            return res
        glance_client = create_glance_client(host_ip)
        qq, resp = glance_client.images.download_chunk(request.chunkNum, vm_info.image_size, request.imageId, False,
                                                       chunk_size=int(config.chunk_size))
        logging.debug("download image: image_size: %s, chunk_num: %s ,chunk_size: %s ", vm_info.image_size,
                      request.chunkNum, config.chunk_size)
        print(len(resp.content))

        res = DownloadVmImageResponse(content=resp.content)
        yield res
