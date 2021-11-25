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

import grpc
from internal.lcmservice import lcmservice_pb2_grpc
from internal.resourcemanager import resourcemanager_pb2_grpc


def _get_secure_channel(options):
    """
    获取ssl通道
    """
    with open('./server_tls.crt', 'rb') as file:
        root_certificates = file.read()
    credentials = grpc.ssl_channel_credentials(root_certificates=root_certificates)
    return grpc.secure_channel(target='mecm-mepm-osplugin:38234',
                               credentials=credentials, options=options)


DEFAULT_OPTIONS = [
    ('grpc.ssl_target_name_override', 'edgegallery.org',),
    ('grpc.max_send_message_length', 50 * 1024 * 1024),
    ('grpc.max_receive_message_length', 50 * 1024 * 1024)]
# channel = _get_secure_channel(DEFAULT_OPTIONS)
channel = grpc.insecure_channel(target='127.0.0.1:8234', options=DEFAULT_OPTIONS)

app_lcm_stub = lcmservice_pb2_grpc.AppLCMStub(channel)
image_stub = resourcemanager_pb2_grpc.VmImageMangerStub(channel)
flavor_stub = resourcemanager_pb2_grpc.FlavorManagerStub(channel)
network_stub = resourcemanager_pb2_grpc.NetworkManagerStub(channel)
security_group_stub = resourcemanager_pb2_grpc.SecurityGroupManagerStub(channel)
server_stub = resourcemanager_pb2_grpc.VmManagerStub(channel)

test_host_ip = '192.168.1.218'
test_tenant_id = 'tenant01'
