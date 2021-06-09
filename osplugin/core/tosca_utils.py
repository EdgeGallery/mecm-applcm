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


def app_security_group():
    return {
        'type': 'tosca.groups.nfv.PortSecurityGroup',
        'properties': {
            'description': 'default security group',
            'name': 'app-group'
        },
        'members': []
    }


def n6_rule(target):
    return {
        'n6_rule': {
            'type': 'tosca.policies.nfv.SecurityGroupRule',
            'targets': [target],
            'properties': {
                'protocol': 0,
                'remote_ip_prefix': {
                    'get_input': 'ue_ip_segment'
                }
            }
        }
    }


def mp1_rule(target):
    return {
        'mp1_rule': {
            'type': 'tosca.policies.nfv.SecurityGroupRule',
            'targets': [target],
            'properties': {
                'protocol': 0,
                'remote_ip_prefix': {
                    'concat': [
                        {
                            'get_input': 'mep_ip'
                        },
                        '/32'
                    ]
                }
            }
        }
    }
