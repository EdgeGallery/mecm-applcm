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
from internal.lcmservice.lcmservice_pb2 import InstantiateRequest
from tests.grpc.client import app_lcm_stub
from tests.resources.gen_token import test_access_token

request = InstantiateRequest(
    accessToken=test_access_token,
    hostIp='192.168.1.218',
    tenantId='tenant01',
    appInstanceId='ins002',
    appPackageId='package-network',
    parameters={},
    akSkLcmGen=False
)

if __name__ == '__main__':
    resp = app_lcm_stub.instantiate(request)
    print(resp)
