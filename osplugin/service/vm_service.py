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

from pony.orm import db_session, commit

import utils
from core.log import logger
from core.models import VmImageInfoMapper
from core.openstack_utils import create_nova_client
from internal.resourcemanager import resourcemanager_pb2_grpc
from internal.resourcemanager.resourcemanager_pb2 import CreateVmResponse, QueryVmResponse, DeleteVmResponse, \
    OperateVmResponse
from task.image_task import start_check_image_status

LOG = logger


class VmService(resourcemanager_pb2_grpc.VmManagerServicer):
    """

    """

    def createVm(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received create vm message')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return CreateVmResponse(status='Failure')

        nova = create_nova_client(host_ip, request.tenantId)

        networks = None
        if request.networks and len(request.networks) > 0:
            networks = []
            for network in request.networks:
                if utils.validate_ipv4_address(network.fixedIp):
                    networks.append({
                        'net-id': network.network,
                        'v4-fixed-ip': network.fixedIp
                    })
                elif network.fixedIp:
                    networks.append({
                        'net-id': network.network,
                        'v6-fixed-ip': network.fixedIp
                    })
                else:
                    networks.append({
                        'net-id': network.network
                    })

        server = nova.servers.create(request.server.name,
                                     request.server.image,
                                     request.server.flavor,
                                     availability_zone=request.server.availablityZone,
                                     config_drive=request.server.configDrive,
                                     security_groups=request.server.securityGroups,
                                     nics=networks,
                                     userdata=request.server.user_data
                                     )
        LOG.info('success boot server %s', server.id)
        return CreateVmResponse(status='Success')

    def queryVm(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received query vm message')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return QueryVmResponse(response='{"code":400}')

        nova = create_nova_client(host_ip, request.tenantId)

        resp_data = {
            'code': 200,
            'msg': 'success'
        }
        if request.vmId is not None:
            resp_data['data'] = nova.servers.get(request.vmId)
        else:
            resp_data['data'] = nova.servers.list()

        LOG.info('success query vm')
        return QueryVmResponse(response=json.dumps(resp_data))

    def operateVm(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received operate vm message')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return OperateVmResponse(response='{"code":400}')

        nova = create_nova_client(host_ip, request.tenantId)

        resp_data = {
            'code': 200,
            'msg': 'success'
        }

        if request.action == 'reboot':
            reboot_type = 'SOFT'
            if request.reboot is not None and request.reboot.type is not None:
                reboot_type = request.reboot.type
            nova.servers.reboot(request.vmId, reboot_type=reboot_type)
        elif request.action == 'createImage':
            resp_data['data'] = nova.servers.create_image(request.vmId,
                                                          request.createImage.name,
                                                          request.createImage.metadata)
            with db_session:
                VmImageInfoMapper(
                    image_id=resp_data['data'],
                    image_name=request.createImage.name,
                    status=utils.QUEUED,
                    host_ip=host_ip,
                    tenant_id=request.tenantId,
                    compress_task_status=utils.WAITING
                )
                commit()
            start_check_image_status(resp_data['data'], host_ip)
            return OperateVmResponse(response=json.dumps(resp_data))
        elif request.action == 'pause':
            nova.servers.pause(request.vmId)
        elif request.action == 'unpause':
            nova.servers.unpause(request.vmId)
        elif request.action == 'suspend':
            nova.servers.suspend(request.vmId)
        elif request.action == 'resume':
            nova.servers.resume(request.vmId)
        elif request.action == 'stop':
            nova.servers.stop(request.vmId)
        elif request.action == 'start':
            nova.servers.start(request.vmId)
        elif request.action == 'createConsole':
            resp_data['data'] = nova.servers.get_console_url(request.vmId, console_type='novnc')
            return OperateVmResponse(response=json.dumps(resp_data))
        else:
            LOG.info('not support action %s', request.action)
            return OperateVmResponse(response='{"code":400,"msg":"not support action %s"}' % request.action)

        LOG.info('success operate vm')
        return OperateVmResponse(response='{"code":200, "msg":"success"}')

    def deleteVm(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received delete vm message')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return DeleteVmResponse(status='Failure')

        nova = create_nova_client(host_ip, request.tenantId)

        nova.servers.delete(request.vmId)

        LOG.info('success delete vm')
        return DeleteVmResponse(status='Success')
