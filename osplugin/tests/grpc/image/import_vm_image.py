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

from internal.resourcemanager.resourcemanager_pb2 import ImportVmImageRequest
from tests.grpc.client import test_host_ip, test_tenant_id, image_stub
from tests.resources.gen_token import test_access_token

import_image_request = ImportVmImageRequest(
    accessToken=test_access_token,
    hostIp=test_host_ip,
    tenantId=test_tenant_id,
    imageId='8b7955ce-6b56-49d6-bfb7-e1677a7fa0a3',
    resourceUri='https://launchpad.net/cirros/trunk/0.3.0/+download/cirros-0.3.0-x86_64-disk.img'
)

if __name__ == '__main__':
    resp = image_stub.importVmImage(import_image_request)
    print(resp)
