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

# !python3
# -*- coding: utf-8 -*-
# !python3
# -*- coding: utf-8 -*-
import grpc

from internal.lcmservice import lcmservice_pb2
from internal.lcmservice import lcmservice_pb2_grpc


def make_upload_request(access_token, host_ip, config_file_data):
    requests = [
        lcmservice_pb2.UploadCfgRequest(accessToken=access_token),
        lcmservice_pb2.UploadCfgRequest(hostIp=host_ip),
        lcmservice_pb2.UploadCfgRequest(configFile=config_file_data)
    ]
    for request in requests:
        yield request


def make_instantiate_request(access_token, app_instance_id, host_ip, package_path, ak, sk):
    with open(package_path, 'rb') as package:
        package_data = package.read()
    requests = [
        lcmservice_pb2.InstantiateRequest(accessToken=access_token),
        lcmservice_pb2.InstantiateRequest(appInstanceId=app_instance_id),
        lcmservice_pb2.InstantiateRequest(hostIp=host_ip),
        lcmservice_pb2.InstantiateRequest(package=package_data),
        lcmservice_pb2.InstantiateRequest(ak=ak),
        lcmservice_pb2.InstantiateRequest(sk=sk)
    ]
    for request in requests:
        yield request


def make_terminate_request(access_token, app_instance_id, host_ip):
    return lcmservice_pb2.TerminateRequest(accessToken=access_token, appInstanceId=app_instance_id, hostIp=host_ip)


if __name__ == '__main__':
    with grpc.insecure_channel('localhost:8234') as channel:
        stub2 = lcmservice_pb2_grpc.AppLCMStub(channel)

        response = stub2.instantiate(make_instantiate_request(access_token="test_access_token",
                                                              app_instance_id="4",
                                                              host_ip='10.10.9.75',
                                                              package_path="./resources/ht-package.zip",
                                                              ak="a",
                                                              sk="s"))
        """
        response = stub2.terminate(make_terminate_request(access_token=test_access_token,
                                                          app_instance_id="4",
                                                          host_ip='10.10.9.75'))"""
        print(str(response))

# stub = lcmservice_pb2_grpc.AppLCMStub(channel)
# stub.terminate(lcmservice_pb2.TerminateRequest(accessToken=test_access_token,
#                                                hostIp=test_host_ip,
#                                                appInstanceId=''))
