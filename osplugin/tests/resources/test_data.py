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

from unittest.mock import Mock

from openstack.compute.v2.server import Server

"""
mock glance client
返回模拟数据
"""
mock_glance_client = Mock()
mock_glance_client.images.get.return_value = {
    'id': 'abc1231234',
    'status': 'active',
    'size': 2014,
    'checksum': '222'
}
mock_glance_client.images.create.return_value = {
    'id': 'abc123123',
    'status': 'queued'
}
mock_glance_client.images.upload.return_value = None
mock_glance_client.images.delete.return_value = None
mock_glance_client.images.data.return_value = [
    b'abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab',
    b'abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab',
    b'abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab',
    b'abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab',
    b'abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab',
    b'abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab',
    b'abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab',
]

"""
mock heat client 返回模拟数据
"""
mock_heat_client = Mock()
mock_heat_client.stacks.create.return_value = {
    'stack': {
        'id': 'created001'
    }
}
mock_heat_client.stacks.delete.return_value = None
mock_heat_client.stacks.output_list.return_value = {
    'outputs': [
        {
            'output_key': 'abcabc'
        }
    ]
}
mock_heat_client.stacks.output_show.return_value = {
    'output': {
        'output_value': {
            'vmId': 'vm001',
            'vncUrl': 'http://127.0.0.1:30010',
            'networks': {
                'mec-mp1': [
                    {
                        'addr': '192.168.1.1'
                    }
                ],
                '25e32a5c-e00f-4edf-b42d-6dd4b610c2db': [
                    {
                        'addr': '192.168.1.1'
                    }
                ],
                'mec-n6': [
                    {
                        'addr': '10.10.121.1'
                    }
                ],
                '25e32a5c-e00f-4edf-b42d-6dd4b610c2dc': [
                    {
                        'addr': '10.10.121.1'
                    }
                ]
            }
        }
    }
}

mock_heat_client.events.list.return_value = [
    {
        'resource_name': 'VM01',
        'event_time': '2020-01-01 00:00:00',
        'resource_status': 'created',
        'resource_status_reason': 'success',
        'logical_resource_id': 'aabbcc',
        'physical_resource_id': 'aabbcc'
    },
    {
        'resource_name': 'VM01',
        'event_time': '2019-12-31 23:59:59',
        'resource_status': 'progressing',
        'resource_status_reason': 'progressing',
        'logical_resource_id': 'aabbcc',
        'physical_resource_id': 'aabbcc'
    }
]

# mock nova client
mock_nova_client = Mock()
server = Server()
server.id = 'aabbccvm01'
server.status = 'active',
server.name = 'vm01'
mock_nova_client.servers.get.return_value = server
mock_nova_client.servers.create_image.return_value = 'aabbccvmimage01'
