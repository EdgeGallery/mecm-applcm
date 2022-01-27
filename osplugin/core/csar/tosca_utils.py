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

APP_SECURITY_GROUP_NAME = 'DefaultSecurityGroup'

SECURITY_GROUP_RULE = 'tosca.policies.nfv.SecurityGroupRule'


def app_security_group():
    """
    生成默认安全组模板，默认允许所有流量出去
    """
    return {
        'type': 'tosca.groups.nfv.PortSecurityGroup',
        'properties': {
            'description': 'default security group',
            'name': 'app-group'
        },
        'members': []
    }


def n6_rule(target):
    """
    生产n6网络规则模板，允许ue_segment网段的源地址流量进入
    param: target 目标安全组
    """
    return {
        'n6_rule': {
            'type': SECURITY_GROUP_RULE,
            'properties': {
                'remote_ip_prefix': {'get_input': 'ue_ip_segment'}
            },
            'targets': [target],
        }
    }


def mp1_rule(target):
    """
    生成mp1网络规则模板，允许mep的流量进入
    """
    return {
        'mp1_rule': {
            'type': SECURITY_GROUP_RULE,
            'properties': {
                'remote_ip_prefix': {'concat': [{'get_input': 'mep_ip'}, '/32']}
            },
            'targets': [target],
        }
    }


def get_data(source, field_name, parameter, appd):
    """

    Args:
        source:
        field_name:
        parameter:
        appd:

    Returns:

    """

    data = getattr(source, field_name, None)
    if data is None:
        return None
    elif type(data) == str:
        return data
    elif type(data) != object or 'get_input' not in data:
        return data
    elif type(data) == object and 'get_input' in data and parameter[data['get_input']] is not None:
        return parameter[data['get_input']]
    else:
        parameter_setting = appd['topology_template']['inputs'][data['get_input']]
        return getattr(parameter_setting, 'default', None)
