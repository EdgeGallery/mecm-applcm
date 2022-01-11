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

# !python3
# -*- coding: utf-8 -*-
import json
import unittest
from unittest import mock

from internal.resourcemanager.resourcemanager_pb2 import CreateNetworkRequest, DeleteNetworkRequest, \
    QueryNetworkRequest, CreateSecurityGroupRequest, DeleteSecurityGroupRequest, QuerySecurityGroupRequest, \
    CreateSecurityGroupRuleRequest, DeleteSecurityGroupRuleRequest
from service.network_service import NetworkService
from service.security_group_service import SecurityGroupService
from tests.resources import gen_token
from tests.resources.test_data import mock_neutron_client


class NetworkServiceTest(unittest.TestCase):
    network_service = NetworkService()
    security_group_service = SecurityGroupService()
    access_token = gen_token.test_access_token
    host_ip = '10.10.9.75'
    tenant_id = 'tenant001'

    @mock.patch('service.network_service.create_neutron_client')
    def test_create_network(self, create_neutron_client):
        create_neutron_client.return_value = mock_neutron_client
        request = CreateNetworkRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            network=CreateNetworkRequest.Network(
                name='test-create-net',
                subnet=CreateNetworkRequest.Network.Subnet(
                    name='192_net',
                    cidr='192.168.111.0/24'
                )
            )
        )
        response = self.network_service.createNetwork(request, None)
        assert response.status == '{"data": null, "retCode": 200, "message": "success"}'

    @mock.patch('service.network_service.create_neutron_client')
    def test_delete_network(self, create_neutron_client):
        create_neutron_client.return_value = mock_neutron_client
        request = DeleteNetworkRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            networkId='ac716e80-71ff-47a1-9eb1-4dd950010678'
        )
        response = self.network_service.deleteNetwork(request, None)
        assert response.status == '{"data": null, "retCode": 0, "message": "Success"}'

    @mock.patch('service.network_service.create_neutron_client')
    def test_query_network(self, create_neutron_client):
        create_neutron_client.return_value = mock_neutron_client
        request = QueryNetworkRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
        )
        response = self.network_service.queryNetwork(request, None)
        resp_data = json.loads(response.response)
        assert len(resp_data['data']) > 0
        request = QueryNetworkRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            networkId='abcabc'
        )
        response = self.network_service.queryNetwork(request, None)
        resp_data = json.loads(response.response)
        assert resp_data['data']['id'] == 'abcabc'

    @mock.patch('service.security_group_service.create_neutron_client')
    def test_create_security_group(self, create_neutron_client):
        create_neutron_client.return_value = mock_neutron_client
        request = CreateSecurityGroupRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            securityGroup=CreateSecurityGroupRequest.SecurityGroup(
                name='test-create'
            )
        )
        response = self.security_group_service.createSecurityGroup(request, None)
        assert response.status == '{"data": null, "retCode": 0, "message": "Success"}'

    @mock.patch('service.security_group_service.create_neutron_client')
    def test_delete_security_group(self, create_neutron_client):
        create_neutron_client.return_value = mock_neutron_client
        request = DeleteSecurityGroupRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            securityGroupId='49427f47-45ee-4042-9d1d-6cb1ea8fd768'
        )
        response = self.security_group_service.deleteSecurityGroup(request, None)
        assert response.status == '{"data": null, "retCode": 200, "message": "success"}'

    @mock.patch('service.security_group_service.create_neutron_client')
    def test_query_security_group(self, create_neutron_client):
        create_neutron_client.return_value = mock_neutron_client
        request = QuerySecurityGroupRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
        )
        response = self.security_group_service.querySecurityGroup(request, None)
        resp_data = json.loads(response.response)
        assert len(resp_data['data']) > 0
        request = QuerySecurityGroupRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            securityGroupId='abcabc'
        )
        response = self.security_group_service.querySecurityGroup(request, None)
        resp_data = json.loads(response.response)
        assert len(resp_data['data']['securityGroupRules']) > 0

    @mock.patch('service.security_group_service.create_neutron_client')
    def test_create_security_rule(self, create_neutron_client):
        create_neutron_client.return_value = mock_neutron_client
        request = CreateSecurityGroupRuleRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            securityGroupRule=CreateSecurityGroupRuleRequest.SecurityGroupRule(
                securityGroupId='49427f47-45ee-4042-9d1d-6cb1ea8fd768',
                remoteIpPrefix='192.168.0.0/24'
            )
        )
        response = self.security_group_service.createSecurityGroupRule(request, None)
        assert response.status == '{"data": null, "retCode":200, "message":"success"}'

    @mock.patch('service.security_group_service.create_neutron_client')
    def test_delete_security_rule(self, create_neutron_client):
        create_neutron_client.return_value = mock_neutron_client
        request = DeleteSecurityGroupRuleRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            securityGroupRuleId='c5ee31ee-d47f-4c6e-960c-e0078504dda1'
        )
        response = self.security_group_service.deleteSecurityGroupRule(request, None)
        assert response.status == '{"data": null, "retCode":200, "message":"success"}'
