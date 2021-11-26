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
from internal.resourcemanager.resourcemanager_pb2 import OperateVmRequest
from tests.grpc.client import server_stub, test_host_ip, test_tenant_id
from tests.resources.gen_token import test_access_token

operate_server = OperateVmRequest(
    accessToken=test_access_token,
    hostIp=test_host_ip,
    tenantId=test_tenant_id,
    vmId='61fcdb06-9375-4711-9fbd-2989a4e0f9a6',
    action='unpause'
)

if __name__ == '__main__':
    resp = server_stub.operateVm(operate_server)
    print(resp)
