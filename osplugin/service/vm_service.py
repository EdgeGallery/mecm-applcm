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

from novaclient.exceptions import NotFound
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
            return CreateVmResponse(status='{"data": null, "retCode": 500, "message": "Failure"}')

        nova = create_nova_client(host_ip, request.tenantId)

        availability_zone = None
        config_drive = None
        security_groups = None
        userdata = None
        networks = None

        if request.server.networks and len(request.server.networks) > 0:
            networks = []
            for network in request.server.networks:
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

        if request.server.availabilityZone:
            availability_zone = request.server.availabilityZone
        if request.server.configDrive:
            config_drive = request.server.configDrive
        if request.server.securityGroups:
            security_groups = request.server.securityGroups
        if request.server.userData:
            userdata = request.server.userData

        server = nova.servers.create(request.server.name,
                                     request.server.image,
                                     request.server.flavor,
                                     availability_zone=availability_zone,
                                     config_drive=config_drive,
                                     security_groups=security_groups,
                                     nics=networks,
                                     userdata=userdata
                                     )
        LOG.info('success boot server %s', server.id)
        return CreateVmResponse(status='{"data": null, "retCode": 0, "message": "Create Success"}')

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
            return QueryVmResponse(response='{"data": null, "retCode":400, "message":"Params invalid"}')

        nova = create_nova_client(host_ip, request.tenantId)

        resp_data = {
            'data': None,
            'retCode': 200,
            'message': 'Success'
        }
        if request.vmId:
            try:
                server = nova.servers.get(request.vmId)
                resp_data['data'] = {
                    'id': server.id,
                    'name': server.name,
                    'status': server.status,
                    'addresses': server.addresses,
                    'flavor': server.flavor,
                    'image': server.image,
                    'securityGroups': server.security_groups
                }
            except NotFound:
                resp_data = {
                    'data': None,
                    'retCode': 404,
                    'message': 'server %s not found' % request.vmId
                }
        else:
            resp_data['data'] = []
            servers = nova.servers.list()
            for server in servers:
                resp_data['data'].append({
                    'id': server.id,
                    'name': server.name,
                    'status': server.status,
                    'addresses': server.addresses,
                    'flavor': server.flavor,
                    'image': server.image,
                    'securityGroups': server.security_groups
                })

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
            return OperateVmResponse(response='{"data": null, "retCode": 400, "message": "hostIp is needed"}')

        nova = create_nova_client(host_ip, request.tenantId)

        resp_data = {
            'data': None,
            'retCode': 200,
            'message': 'Success'
        }

        if request.action == 'reboot':
            reboot_type = 'SOFT'
            if request.reboot is not None and request.reboot.type is not None:
                reboot_type = request.reboot.type
            nova.servers.reboot(request.vmId, reboot_type=reboot_type)
        elif request.action == 'createImage':
            metadata = None
            if request.createImage.metadata:
                metadata = dict(request.createImage.metadata)
            resp_data['data'] = nova.servers.create_image(request.vmId,
                                                          request.createImage.name,
                                                          metadata=metadata)
            with db_session:
                VmImageInfoMapper(
                    image_id=resp_data['data'],
                    image_name=request.createImage.name,
                    disk_format='raw',
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
            return OperateVmResponse(response='{"data": null, "retCode": 400,"message": "not support action %s"}'
                                              % request.action)

        LOG.info('success operate vm')
        return OperateVmResponse(response='{"data": null, "retCode": 200, "message": "success"}')

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
            return DeleteVmResponse(status='{"data": null, "retCode": 500, "message": "Failure"}')

        nova = create_nova_client(host_ip, request.tenantId)

        try:
            nova.servers.delete(request.vmId)
        except NotFound:
            LOG.debug('skip not found server %s', request.vmId)

        LOG.info('success delete vm')
        return DeleteVmResponse(status='{"data": null, "retCode":200, "message":"success"}')
