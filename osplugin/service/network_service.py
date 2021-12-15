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

from neutronclient.common.exceptions import NotFound, NeutronClientException

import utils
from core.log import logger
from core.openstack_utils import create_neutron_client
from internal.resourcemanager import resourcemanager_pb2_grpc
from internal.resourcemanager.resourcemanager_pb2 import CreateNetworkResponse, DeleteNetworkResponse, \
    QueryNetworkResponse

LOG = logger


class NetworkService(resourcemanager_pb2_grpc.NetworkManagerServicer):
    """

    """

    def createNetwork(self, request, context):
        """
        创建网络
        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received create network message')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return CreateNetworkResponse(status='{"data": null, "retCode": 500, "message": "Failure"}')

        neutron = create_neutron_client(host_ip, request.tenantId)

        network_data = {
            'name': request.network.name,
            'admin_state_up': request.network.adminStateUp or True,
            'router:external': request.network.routerExternal or False,
            'shared': request.network.shared or False,
            'is_default': request.network.isDefault or False
        }
        if request.network.mtu:
            network_data['mtu'] = request.network.mtu
        if request.network.providerNetworkType:
            network_data['provider:network_type'] = request.network.providerNetworkType
        if request.network.providerPhysicalNetwork:
            network_data['provider:physical_network'] = request.network.providerPhysicalNetwork
        if request.network.providerSegmentationId:
            network_data['provider:segmentation_id'] = request.network.providerSegmentationId
        if request.network.qosPolicyId:
            network_data['qos_policy_id'] = request.network.qosPolicyId
        if request.network.segments:
            network_data['segments'] = []
        for segment in request.network.segments:
            network_data['segments'].append({
                'provider_segmentation_id': segment.providerSegmentationId or None,
                'provider_physical_network': segment.providerPhysicalNetwork or None,
                'provider_network_type': segment.providerNetworkType or None
            })

        network = neutron.create_network({'network': network_data})['network']

        LOG.info('resp network %s', network)

        if request.network.subnet:
            req_subnet = request.network.subnet
            subnet_data = {
                'name': req_subnet.name,
                'cidr': req_subnet.cidr,
                'enable_dhcp': req_subnet.enableDhcp or True,
                'network_id': network['id'],
                'ip_version': req_subnet.ipVersion or 4,
            }
            if req_subnet.dnsNameservers:
                subnet_data['dns_nameservers'] = req_subnet.dnsNameservers
            if req_subnet.gatewayIp:
                subnet_data['gateway_ip'] = req_subnet.gatewayIp
            if req_subnet.ipv6AddressMode:
                subnet_data['ipv6_address_mode'] = req_subnet.ipv6AddressMode
            if req_subnet.ipv6RaMode:
                subnet_data['ipv6_ra_mode'] = req_subnet.ipv6RaMode
            if req_subnet.allocationPools:
                subnet_data['allocation_pools'] = []
                for req_pool in req_subnet.allocationPools:
                    subnet_data['allocation_pools'].append({
                        'start': req_pool.start or None,
                        'end': req_pool.end or None
                    })
            neutron.create_subnet({'subnet': subnet_data})

        LOG.info("success create network %s", network)

        return CreateNetworkResponse(status='{"data": null, "retCode": 200, "message": "success"}')

    def deleteNetwork(self, request, context):
        """
        删除网络
        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received delete network message')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return DeleteNetworkResponse(status='{"data": null, "retCode": 500, "message": "Failure"}')
        neutron = create_neutron_client(host_ip, request.tenantId)

        try:
            neutron.delete_network(request.networkId)
        except NotFound:
            LOG.debug('skip not found network %s', request.networkId)
            return DeleteNetworkResponse(status='{"data": null, "retCode": 404, "message": "Network not found"}')
        LOG.info("success delete network %s", request.networkId)
        return DeleteNetworkResponse(status='{"data": null, "retCode": 0, "message": "Success"}')

    def queryNetwork(self, request, context):
        """
        查询网络信息
        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received query network message')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return QueryNetworkResponse(response='{"data": null, "retCode": 400, "message": "hostIp is needed"}')
        neutron = create_neutron_client(host_ip, request.tenantId)

        resp_data = {
            'retCode': 200,
            'message': 'success'
        }
        if not request.networkId:
            networks = neutron.list_networks()['networks']
            resp_data['data'] = []
            for network in networks:
                network_data = {
                    'id': network['id'],
                    'name': network['name'],
                    'shared': network['shared'],
                    'external': network['router:external'],
                    'status': network['status'],
                    'adminState': network['admin_state_up'],
                    'availabilityZones': network['availability_zones'],
                    'subnets': []
                }
                for subnet_id in network['subnets']:
                    try:
                        subnet = neutron.show_subnet(subnet_id)['subnet']
                        network_data['subnets'].append({'cidr': subnet['cidr'], 'name': subnet['name']})
                    except NeutronClientException:
                        network_data['subnets'].append({'cidr': '', 'name': ''})
                resp_data['data'].append(network_data)

        else:
            network = neutron.show_network(request.networkId)['network']
            subnets = []
            for subnet_id in network['subnets']:
                subnets.append(neutron.show_subnet(subnet_id)['subnet'])
            network['subnets'] = subnets
            resp_data['data'] = network

        LOG.info("success query network")
        return QueryNetworkResponse(response=json.dumps(resp_data))
