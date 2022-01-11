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
    'checksum': '222',
    'disk_format': 'qcow2'
}
mock_glance_client.images.create.return_value = {
    'id': 'abc123123',
    'name': 'test',
    'status': 'queued'
}
mock_glance_client.images.list.return_value = [
    {
        'id': 'abc1231234',
        'name': 'name',
        'status': 'active',
        'size': 2014,
        'checksum': '222',
        'disk_format': 'qcow2',
        'visibility': True,
        'protected': True
    }
]
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


class MockStack:
    def __init__(self, _dict):
        self.status = _dict['status']
        self.action = _dict['action']
        self.stack_status = _dict['stack_status']
        self.stack_status_reason = _dict['reason']


mock_heat_client = Mock()
mock_heat_client.stacks.get.return_value = MockStack({
    'status': 'FAILED',
    'action': 'CREATE',
    'stack_status': 'CREATE_FAILED',
    'reason': 'test create failed'
})
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

# mock neutron client
network_data = {
    'id': 'abcabc',
    'name': 'test-net',
    'shared': False,
    'router:external': False,
    'status': 'active',
    'admin_state_up': True,
    'availability_zones': 'nova',
    'subnets': ['abcabc']
}
subnet_data = {
    'id': 'abcabc',
    'cidr': '192.168.10.0/24',
    'name': 'test-subnet'
}
security_group_data = {
    'id': 'abcabc',
    'name': 'test-security-group',
    'security_group_rules': [
        {
            'id': 'abcabc',
            'protocol': 'any',
            'remote_group_id': 'abcabc',
            'ethertype': 'IPv4',
            'direction': 'ingress',
            'port_range_max': None,
            'port_range_min': None,
            'remote_ip_prefix': None
        }
    ]
}
mock_neutron_client = Mock()
mock_neutron_client.create_network.return_value = {
    'network': network_data
}
mock_neutron_client.show_network.return_value = {
    'network': network_data
}
mock_neutron_client.create_subnet.return_value = {
    'subnet': subnet_data
}
mock_neutron_client.delete_network.return_value = None
mock_neutron_client.list_networks.return_value = {
    'networks': [network_data]
}
mock_neutron_client.show_subnet.return_value = {
    'subnet': subnet_data
}
mock_neutron_client.create_security_group.return_value = None
mock_neutron_client.delete_security_group.return_value = None
mock_neutron_client.show_security_group.return_value = {
    'security_group': security_group_data
}
mock_neutron_client.list_security_groups.return_value = {
    'security_groups': [security_group_data]
}
mock_neutron_client.create_security_group_rule.return_value = None
mock_neutron_client.delete_security_group_rule.return_value = None


# mock nova client
class MockFlavor:
    """

    """

    def __init__(self):
        self.id = 'abcabc'
        self.name = 'abcabc'
        self.vcpus = 1,
        self.ram = 1024,
        self.disk = 10,
        self.rxtx_factor = 1.0,
        self.ephemeral = 0,
        self.is_public = True

    def get_keys(self):
        """

        Returns:

        """
        return {
            'test1': 'test1'
        }


mock_nova_client = Mock()
server = Server()
server.id = 'aabbccvm01'
server.status = 'active',
server.name = 'vm01'
mock_nova_client.servers.get.return_value = server
mock_nova_client.servers.list.return_value = [server]
mock_nova_client.servers.create_image.return_value = 'aabbccvmimage01'
mock_nova_client.servers.create.return_value = server
mock_nova_client.servers.delete.return_value = None
mock_nova_client.servers.reboot.return_value = None
mock_nova_client.servers.pause.return_value = None
mock_nova_client.servers.unpause.return_value = None
mock_nova_client.servers.suspend.return_value = None
mock_nova_client.servers.resume.return_value = None
mock_nova_client.servers.stop.return_value = None
mock_nova_client.servers.start.return_value = None
mock_nova_client.servers.get_console_url.return_value = 'http://127.0.0.1:6080/novnc.html?token=abcabcabc'

flavor = Mock()
flavor.set_keys.return_value = None
mock_nova_client.flavors.create.return_value = flavor
mock_nova_client.flavors.list.return_value = [MockFlavor()]
mock_nova_client.flavors.get.return_value = MockFlavor()


class MockResponse:
    """

    """

    def __init__(self, params):
        self.status_code = params['status_code']
        self.data = params['json']

    def json(self):
        """

        Returns:

        """
        return self.data
