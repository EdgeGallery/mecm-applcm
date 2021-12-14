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

from novaclient.exceptions import NotFound, ClientException

import utils
from core.log import logger
from core.openstack_utils import create_nova_client
from internal.resourcemanager import resourcemanager_pb2_grpc
from internal.resourcemanager.resourcemanager_pb2 import CreateFlavorResponse, DeleteFlavorResponse, QueryFlavorResponse

LOG = logger


class FlavorService(resourcemanager_pb2_grpc.FlavorManagerServicer):
    """

    """

    def createFlavor(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received create flavor message')
        resp = CreateFlavorResponse(status='Failure')

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return resp

        nova = create_nova_client(host_ip, request.tenantId)

        try:
            flavor = nova.flavors.create(name=request.flavor.name,
                                         ram=request.flavor.ram,
                                         vcpus=request.flavor.vcpus,
                                         disk=request.flavor.disk,
                                         swap=request.flavor.swap)
        except ClientException as client_exception:
            resp.status = json.dumps({
                'data': None,
                'retCode': client_exception.code,
                'message': client_exception.message
            })
            return resp

        if request.flavor.extraSpecs:
            flavor.set_keys(dict(request.flavor.extraSpecs))

        LOG.info('success create flavor %s', flavor)
        resp.status = json.dumps({
            'data': null,
            'retCode': 0,
            'message': 'Success'
        })
        return resp

    def deleteFlavor(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received delete flavor message')
        resp = DeleteFlavorResponse(status='Failure')

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return resp

        nova = create_nova_client(host_ip, request.tenantId)

        try:
            nova.flavors.delete(request.flavorId)
        except NotFound:
            LOG.debug('flavor not found, skip delete')
        LOG.info('success delete flavor %s', request.flavorId)
        resp.status = json.dumps({
            'data': None,
            'retCode': 0,
            'message': 'Success'
        })
        return resp

    def queryFlavor(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received query flavor message')
        resp = QueryFlavorResponse(response='{"retCode": 500, "message": "failure"}')

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return resp

        nova = create_nova_client(host_ip, request.tenantId)

        resp_data = {
            'data': None,
            'retCode': 200,
            'message': 'success'
        }

        if not request.flavorId:
            resp_data['data'] = []
            flavors = nova.flavors.list()
            for flavor in flavors:
                resp_data['data'].append({
                    'id': flavor.id,
                    'description': getattr(flavor, 'description', None),
                    'name': flavor.name,
                    'vcpus': flavor.vcpus,
                    'ram': flavor.ram,
                    'disk': flavor.disk,
                    'rxtx': flavor.rxtx_factor,
                    'ephemeralDisk': flavor.ephemeral,
                    'isPublic': flavor.is_public,
                })
        else:
            try:
                flavor = nova.flavors.get(request.flavorId)
                logger.info(flavor)
                extra_specs = flavor.get_keys()
                resp_data['data'] = {
                    'id': flavor.id,
                    'description': getattr(flavor, 'description', None),
                    'name': flavor.name,
                    'vcpus': flavor.vcpus,
                    'ram': flavor.ram,
                    'disk': flavor.disk,
                    'rxtx': flavor.rxtx_factor,
                    'ephemeralDisk': flavor.ephemeral,
                    'isPublic': flavor.is_public,
                    'extraSpecs': dict(extra_specs)
                }
            except NotFound:
                resp_data['data'] = None
                resp_data['retCode'] = 404
                resp_data['message'] = 'flavor %s not found' % request.flavorId

        resp.response = json.dumps(resp_data)

        LOG.info('query flavor message success')
        return resp
