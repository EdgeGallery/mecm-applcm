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


# !python3
# -*- coding: utf-8 -*-
import grpc

from internal.lcmservice import lcmservice_pb2
from internal.lcmservice import lcmservice_pb2_grpc
from tests.test_data import test_host_ip


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


def make_create_image_request(access_token, host_ip, app_instance_id, vm_id):
    return lcmservice_pb2.CreateVmImageRequest(accessToken=access_token, hostIp=host_ip, appInstanceId=app_instance_id,
                                               vmId=vm_id)


def make_delete_image_request(access_token, host_ip, app_instance_id, image_id):
    return lcmservice_pb2.DeleteVmImageRequest(accessToken=access_token, hostIp=host_ip, appInstanceId=app_instance_id,
                                               imageId=image_id)


def make_download_image_request(access_token, chunk_num, host_ip, app_instance_id, image_id):
    return lcmservice_pb2.DownloadVmImageRequest(accessToken=access_token, hostIp=host_ip, chunkNum=chunk_num,
                                                 appInstanceId=app_instance_id,
                                                 imageId=image_id)


if __name__ == '__main__':
    with grpc.insecure_channel('localhost:8234') as channel:
        stub = lcmservice_pb2_grpc.VmImageStub(channel)
        response = stub.createVmImage(
            make_create_image_request(access_token="test_access_token", host_ip=test_host_ip, app_instance_id="1",
                                      vm_id="2fd65cfb-fa1e-4461-bc40-326a55f01803"))

        # response = stub.deleteVmImage(
        #     make_delete_image_request(access_token="test_access_token", host_ip=test_host_ip, app_instance_id="1",
        #                               image_id="98920865-8c34-4f32-a166-f7c06775a34a"))

        # response = stub.queryVmImage(
        #     make_delete_image_request(access_token="test_access_token", host_ip=test_host_ip, app_instance_id="1",
        #                               image_id="bbbcb967-bb32-4185-9b00-6c4b464535a9"))

        # response = stub.downloadVmImage(
        #     make_download_image_request(access_token="test_access_token", host_ip=test_host_ip, chunk_num=1,
        #                                app_instance_id="1", image_id="bbbcb967-bb32-4185-9b00-6c4b464535a9"))

        # for i in range(1, 12975):
        #     response = stub.downloadVmImage(
        #         make_download_image_request(access_token="test_access_token", host_ip=test_host_ip, chunk_num=i,
        #                                     app_instance_id="1", image_id="bbc25da6-47e9-4940-ad75-5e5ddda8a36f"))
        #     file = open('image.QCOW2', 'ab')
        #     print(response)
        #     for res in response:
        #         print(res)
        #         file.write(res.content)
# stub = lcmservice_pb2_grpc.AppLCMStub(channel)
# stub.terminate(lcmservice_pb2.TerminateRequest(accessToken=test_access_token,
#                                                hostIp=test_host_ip,
#                                                appInstanceId=''))
