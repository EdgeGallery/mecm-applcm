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
            return CreateNetworkResponse(status='Failure')
        neutron = create_neutron_client(host_ip, request.tenantId)

        network_data = {
            'name': request.network.name,
            'admin_state_up': request.network.adminStateUp,
            'dns_domain': request.network.dnsDomain,
            'mtu': request.network.mtu,
            'port_security_enable': request.network.portSecurityEnabled,
            'provider:network_type': request.network.providerNetworkType,
            'provider:physical_network': request.network.providerPhysicalNetwork,
            'provider:segmentation_id': request.network.providerSegmentationId,
            'qos_policy_id': request.network.qosPolicyId,
            'router:external': request.network.routerExternal,
            'segments': [],
            'shared': request.network.shared,
            'vlan_transparent': request.network.vlanTransparent,
            'is_default': request.network.isDefault,
        }

        for segment in request.network.segments:
            network_data['segments'].append({
                'provider_segmentation_id': segment.providerSegmentationId,
                'provider_physical_network': segment.providerPhysicalNetwork,
                'provider_network_type': segment.providerNetworkType
            })

        network = neutron.create_network({'network': network_data})

        LOG.info('resp network %s', network)

        for req_subnet in request.network.subnets:
            subnet_data = {
                'name': req_subnet.name,
                'enable_dhcp': req_subnet.enableDhcp,
                'network_id': network['id'],
                'dns_nameservers': req_subnet.dnsNamesevers,
                'allocation_pools': [],
                'ip_version': req_subnet.ipVersion,
                'gateway_ip': req_subnet.gatewayIp,
                'cidr': req_subnet.cidr,
                'ipv6_address_mode': req_subnet.ipv6AddressMode,
                'ipv6_ra_mode': req_subnet.ipv6RaMode
            }
            for req_pool in req_subnet.allocationPools:
                subnet_data['allocation_pools'].append({
                    'start': req_pool.start,
                    'end': req_pool.end
                })
            neutron.create_subnet({'subnet': subnet_data})

        LOG.info("success create network %s", network)
        return CreateNetworkResponse(status='Success')

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
            return DeleteNetworkResponse(status='Failure')
        neutron = create_neutron_client(host_ip, request.tenantId)

        neutron.delete_network(request.networkId)
        LOG.info("success delete network %s", request.networkId)
        return DeleteNetworkResponse(status='Success')

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
            return QueryNetworkResponse(response='{"code":400, "msg":"hostIp必传"}')
        neutron = create_neutron_client(host_ip, request.tenantId)

        resp_data = {
            'code': 200,
            'msg': 'success'
        }
        if request.networkId is not None:
            resp_data['data'] = neutron.show_network(request.networkId)
        else:
            resp_data['data'] = neutron.list_networks()

        LOG.info("success query network")
        return QueryNetworkResponse(response=json.dumps(resp_data))
