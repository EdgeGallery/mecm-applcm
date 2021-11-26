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
from internal.resourcemanager.resourcemanager_pb2 import CreateVmRequest
from tests.grpc.client import server_stub, test_host_ip, test_tenant_id
from tests.resources.gen_token import test_access_token

create_server = CreateVmRequest(
    accessToken=test_access_token,
    hostIp=test_host_ip,
    tenantId=test_tenant_id,
    server=CreateVmRequest.Server(
        name='testVm',
        flavor='22e1a2f4-9f75-4baa-a6e4-f613deebc4ca',
        image='783b1d93-3c23-4e4c-a0ed-98ca27137628',
        networks=[
            CreateVmRequest.Server.Network(
                network='32b0f4fd-66ba-44b4-8a7e-ccdb0d7dc61e'
            )
        ]
    )
)

if __name__ == '__main__':
    resp = server_stub.createVm(create_server)
    print(resp)
