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

from internal.resourcemanager.resourcemanager_pb2 import UploadVmImageRequest
from tests.grpc.client import test_host_ip, test_tenant_id, image_stub
from tests.resources.gen_token import test_access_token


def gen_request():
    yield UploadVmImageRequest(accessToken=test_access_token)
    yield UploadVmImageRequest(hostIp=test_host_ip)
    yield UploadVmImageRequest(tenantId=test_tenant_id)
    yield UploadVmImageRequest(imageId='783b1d93-3c23-4e4c-a0ed-98ca27137628')

    with open('/Users/cuijch/Downloads/cirros-0.5.2-x86_64-disk.img', 'rb') as file:
        while True:
            content = file.read(1024 * 1024)
            if not content:
                break
            yield UploadVmImageRequest(content=content)


if __name__ == '__main__':
    resp = image_stub.uploadVmImage(gen_request())
    print(resp)
