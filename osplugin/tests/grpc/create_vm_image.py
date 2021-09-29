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
from internal.lcmservice import lcmservice_pb2
from tests.grpc.client import vm_image_stub
from tests.resources.gen_token import test_access_token


request = lcmservice_pb2.CreateVmImageRequest(
    accessToken=test_access_token,
    tenantId='abcabc',
    hostIp='10.10.9.75',
    appInstanceId='appIns001',
    vmId='447a9e1b-3ca8-49c3-9edd-d1d63809dede')


if __name__ == '__main__':
    response = vm_image_stub.createVmImage(request)
    print(response)
