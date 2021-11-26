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

from internal.resourcemanager.resourcemanager_pb2 import CreateFlavorRequest
from tests.grpc.client import flavor_stub, test_host_ip, test_tenant_id
from tests.resources.gen_token import test_access_token

create_flavor_request = CreateFlavorRequest(
    accessToken=test_access_token,
    tenantId=test_tenant_id,
    hostIp=test_host_ip,
    flavor=CreateFlavorRequest.Flavor(
        name='test-create-flavor',
        vcpus=1,
        ram=1024,
        disk=20,
        extraSpecs={
            'x86': 'true'
        }
    )
)

if __name__ == '__main__':
    resp = flavor_stub.createFlavor(create_flavor_request)
    print(resp)
