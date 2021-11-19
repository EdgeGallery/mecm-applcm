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

        flavor = nova.flavors.create(name=request.flavor.name,
                                     ram=request.flavor.ram,
                                     vcpus=request.flavor.vcpus,
                                     disk=request.flavor.disk,
                                     swap=request.flavor.swap)

        if request.extraSpecs is not None:
            flavor.set_keys(request.extraSpecs)

        LOG.info('success create flavor %s', flavor)
        resp.status = 'Success'
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

        nova.flavors.delete(request.flavorId)
        LOG.info('success delete flavor %s', request.flavorId)
        resp.status = 'Success'
        return resp

    def queryFlavor(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received query flavor message')
        resp = QueryFlavorResponse(response='{"code": 500, "msg": "failure"}')

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return resp

        nova = create_nova_client(host_ip, request.tenantId)

        resp_data = {
            'code': 200,
            'msg': 'success'
        }

        if request.flavorId is not None:
            resp_data['data'] = nova.flavors.get(request.flavorId)
        else:
            resp_data['data'] = nova.flavors.list()
        resp.response = json.dumps(resp_data)

        LOG.info('query flavor message success')
        return resp
