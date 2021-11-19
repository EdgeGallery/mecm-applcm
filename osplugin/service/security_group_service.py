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
from internal.resourcemanager.resourcemanager_pb2 import CreateSecurityGroupResponse, DeleteSecurityGroupResponse, \
    QuerySecurityGroupResponse, CreateSecurityGroupRuleResponse, DeleteSecurityGroupRuleResponse, \
    QuerySecurityGroupRuleResponse

LOG = logger


class SecurityGroupService(resourcemanager_pb2_grpc.SecurityGroupManagerServicer):
    """

    """

    def createSecurityGroup(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received create security group message')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return CreateSecurityGroupResponse(status='Failure')
        neutron = create_neutron_client(host_ip, request.tenantId)

        security_group = {
            'name': request.securityGroup.name
        }
        neutron.create_security_group({'security_group': security_group})
        LOG.info('create security group success')
        return CreateSecurityGroupResponse(status='Success')

    def deleteSecurityGroup(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info("received delete security group message")
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return DeleteSecurityGroupResponse(status='Failure')

        neutron = create_neutron_client(host_ip, request.tenantId)

        neutron.delete_security_group(request.securityGroupId)
        LOG.info("delete security group success")

        return DeleteSecurityGroupResponse(status='Success')

    def querySecurityGroup(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info("received delete security group message")
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return QuerySecurityGroupResponse(response='{"code":400,"msg":"error"}')

        neutron = create_neutron_client(host_ip, request.tenantId)

        resp_data = {
            'code': 200,
            'msg': 'success'
        }
        if request.securityGroupId is not None:
            resp_data['data'] = neutron.show_security_group(request.securityGroupId)
        else:
            resp_data['data'] = neutron.list_security_groups()

        LOG.info("success query security group")
        return QuerySecurityGroupResponse(response=json.dumps(resp_data))

    def createSecurityGroupRule(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info("received security group rule message")
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return CreateSecurityGroupRuleResponse(status='Failure')

        neutron = create_neutron_client(host_ip, request.tenantId)

        security_group_rule = {
            'security_group_id': request.securityGroupRule.securityGroupId,
            'direction': request.securityGroupRule.direction,
            'protocol': request.securityGroupRule.protocol,
            'ethertype': request.securityGroupRule.ethertype,
            'port_range_max': request.securityGroupRule.portRangeMax,
            'port_range_min': request.securityGroupRule.portRangeMin,
            'remote_ip_prefix': request.securityGroupRule.remoteIpPrefix,
            'remote_group_id': request.securityGroupRule.remoteGroupId
        }
        neutron.create_security_group_rule({'security_group_rule': security_group_rule})

        LOG.info("success create security group rule")

        return CreateSecurityGroupRuleResponse(status='Success')

    def deleteSecurityGroupRule(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received delete security group rule message')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return DeleteSecurityGroupRuleResponse(status='Failure')

        neutron = create_neutron_client(host_ip, request.tenantId)

        neutron.delete_security_group_rule(request.securityGroupRuleId)

        LOG.info('success delete security group rule')

        return DeleteSecurityGroupRuleResponse(status='success')

    def querySecurityGroupRule(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received query security group rule message')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return QuerySecurityGroupRuleResponse(response='{"code":400}')

        neutron = create_neutron_client(host_ip, request.tenantId)

        resp_data = {
            'code': 200,
            'msg': 'success'
        }
        if request.securityGroupRuleId is not None:
            resp_data['data'] = neutron.show_security_group_rule(request.securityGroupRuleId)
        else:
            resp_data['data'] = neutron.list_security_group_rules(security_group=request.securityGroupId)

        LOG.info('success query security group rule message')
        return QuerySecurityGroupRuleResponse(response=json.dumps(resp_data))
