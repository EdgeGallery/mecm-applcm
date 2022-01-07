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

from neutronclient.common.exceptions import NotFound

import utils
from core.log import logger
from core.openstack_utils import create_neutron_client
from internal.resourcemanager import resourcemanager_pb2_grpc
from internal.resourcemanager.resourcemanager_pb2 import CreateSecurityGroupResponse, DeleteSecurityGroupResponse, \
    QuerySecurityGroupResponse, CreateSecurityGroupRuleResponse, DeleteSecurityGroupRuleResponse

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
            return CreateSecurityGroupResponse(status='{"data": null, "retCode": 400, "message": "hostIp is needed"}')
        neutron = create_neutron_client(host_ip, request.tenantId)

        security_group = {
            'name': request.securityGroup.name
        }
        neutron.create_security_group({'security_group': security_group})
        LOG.info('create security group success')
        return CreateSecurityGroupResponse(status='{"data": null, "retCode": 0, "message": "Success"}')

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
            return DeleteSecurityGroupResponse(status='{"data": null, "retCode": 400, "message": "hostIp is needed"}')

        neutron = create_neutron_client(host_ip, request.tenantId)

        try:
            neutron.delete_security_group(request.securityGroupId)
        except NotFound:
            LOG.debug('skip not found security group %s', request.securityGroupId)
        LOG.info("delete security group success")

        return DeleteSecurityGroupResponse(status='{"data": null, "retCode": 200, "message": "success"}')

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
            return QuerySecurityGroupResponse(response='{"data": null, "retCode": 400, "message": "params invalid"}')

        neutron = create_neutron_client(host_ip, request.tenantId)

        resp_data = {
            'data': None,
            'retCode': 200,
            'message': 'success'
        }
        if request.securityGroupId:
            try:
                security_group = neutron.show_security_group(request.securityGroupId)['security_group']
                resp_data['data'] = {
                    'id': security_group['id'],
                    'name': security_group['name'],
                    'securityGroupRules': []
                }
                for security_rule in security_group['security_group_rules']:
                    resp_data['data']['securityGroupRules'].append({
                        'id': security_rule['id'],
                        'protocol': security_rule['protocol'],
                        'portRangeMax': security_rule['port_range_max'],
                        'portRangeMin': security_rule['port_range_min'],
                        'remoteGroupId': security_rule['remote_group_id'],
                        'remoteIpPrefix': security_rule['remote_ip_prefix'],
                        'ethertype': security_rule['ethertype'],
                        'direction': security_rule['direction']
                    })
            except NotFound:
                resp_data['data'] = None
                resp_data['retCode'] = 404
                resp_data['message'] = 'security group %s not found' % request.securityGroupId
        else:
            resp_data['data'] = []
            security_groups = neutron.list_security_groups()['security_groups']
            for security_group in security_groups:
                resp_data['data'].append({
                    'id': security_group['id'],
                    'name': security_group['name']
                })

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
            return CreateSecurityGroupRuleResponse(status='{"data": null, "retCode": 500, "message": "Failure"}')

        neutron = create_neutron_client(host_ip, request.tenantId)

        security_group_rule = {
            'security_group_id': request.securityGroupRule.securityGroupId,
            'direction': request.securityGroupRule.direction or 'ingress',
            'ethertype': request.securityGroupRule.ethertype or 'IPv4',
            'protocol': request.securityGroupRule.protocol or 'any'
        }
        if request.securityGroupRule.portRangeMax:
            security_group_rule['port_range_max'] = request.securityGroupRule.portRangeMax
        if request.securityGroupRule.portRangeMin:
            security_group_rule['port_range_min'] = request.securityGroupRule.portRangeMin
        if request.securityGroupRule.remoteIpPrefix:
            security_group_rule['remote_ip_prefix'] = request.securityGroupRule.remoteIpPrefix
        if request.securityGroupRule.remoteGroupId:
            security_group_rule['remote_group_id'] = request.securityGroupRule.remoteGroupId
        neutron.create_security_group_rule({'security_group_rule': security_group_rule})

        LOG.info("success create security group rule")

        return CreateSecurityGroupRuleResponse(status='{"data": null, "retCode":200, "message":"success"}')

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
            return DeleteSecurityGroupRuleResponse(status='{"data": null, "retCode": 500, "message": "Failure"}')

        neutron = create_neutron_client(host_ip, request.tenantId)

        try:
            neutron.delete_security_group_rule(request.securityGroupRuleId)
        except NotFound:
            LOG.debug('skip not found security rule %s', request.securityGroupRuleId)

        LOG.info('success delete security group rule')

        return DeleteSecurityGroupRuleResponse(status='{"data": null, "retCode":200, "message":"success"}')
