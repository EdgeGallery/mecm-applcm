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
from internal.lcmservice.lcmservice_pb2 import UploadPackageRequest
from tests.grpc.client import app_lcm_stub
from tests.resources.gen_token import test_access_token


def upload_pkg_req():
    yield UploadPackageRequest(accessToken=test_access_token)
    yield UploadPackageRequest(hostIp='192.168.1.218')
    yield UploadPackageRequest(tenantId='tenant01')
    yield UploadPackageRequest(appPackageId='package-iso1')
    with open('../../resources/test_iso.zip', 'rb') as file:
        while True:
            content = file.read(1024 * 1024)
            if not content:
                break
            yield UploadPackageRequest(package=content)
    print('upload finished')


if __name__ == '__main__':
    resp = app_lcm_stub.uploadPackage(upload_pkg_req())
    print(resp)
