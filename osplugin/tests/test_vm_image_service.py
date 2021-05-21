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

import unittest
from internal.lcmservice import lcmservice_pb2
from service.vm_image_service import VmImageService
from tests import gen_token


def make_create_image_request(access_token, host_ip, app_instance_id, vm_id):
    """
    make_create_image_request
    """
    return lcmservice_pb2.CreateVmImageRequest(accessToken=access_token,
                                               hostIp=host_ip,
                                               appInstanceId=app_instance_id,
                                               vmId=vm_id)


def make_delete_image_request(access_token, host_ip, app_instance_id, image_id):
    """
    make_delete_image_request
    """
    return lcmservice_pb2.DeleteVmImageRequest(accessToken=access_token,
                                               hostIp=host_ip,
                                               appInstanceId=app_instance_id,
                                               imageId=image_id)


def make_query_image_request(access_token, host_ip, app_instance_id, image_id):
    """
    make_delete_image_request
    """
    return lcmservice_pb2.QueryVmImageRequest(accessToken=access_token,
                                              hostIp=host_ip,
                                              appInstanceId=app_instance_id,
                                              imageId=image_id)


def make_download_image_request(access_token, chunk_num, host_ip, app_instance_id, image_id):
    """
    make_download_image_request
    """
    return lcmservice_pb2.DownloadVmImageRequest(accessToken=access_token,
                                                 hostIp=host_ip,
                                                 chunkNum=chunk_num,
                                                 appInstanceId=app_instance_id,
                                                 imageId=image_id)


class VmImageServiceTest(unittest.TestCase):
    """
    测试镜像service
    """
    vm_image_service = VmImageService()
    access_token = gen_token.test_access_token
    host_ip = '10.10.9.75'

    def test_create_image(self):
        """
        test_create_image
        """
        request = make_create_image_request(access_token=self.access_token,
                                            host_ip=self.host_ip,
                                            app_instance_id="1",
                                            vm_id="caf83c05-56dc-4f7c-b417-40d9acbf166c")
        res = self.vm_image_service.createVmImage(request, None)
        print(res)

    def test_delete_image(self):
        """
        test_delete_image
        """
        request = make_delete_image_request(access_token=self.access_token,
                                            host_ip=self.host_ip,
                                            app_instance_id="1",
                                            image_id="2fd65cfb-fa1e-4461-bc40-326a55f01803")
        res = self.vm_image_service.deleteVmImage(request, None)
        print(res)

    def test_query_image(self):
        """
        test_query_image
        """
        request = make_query_image_request(access_token=self.access_token,
                                            host_ip=self.host_ip,
                                            app_instance_id="1",
                                            image_id="e8360231-14fe-4baf-b34a-5be17c62e2f8")
        res = self.vm_image_service.queryVmImage(request, None)
        print(res)

    def test_download_image(self):
        """
        test_download_image
        """
        request = make_download_image_request(access_token=self.access_token,
                                              host_ip=self.host_ip,
                                              app_instance_id="1",
                                              chunk_num=1,
                                              image_id="f95bcbb1-e1e2-4aaf-872c-f0c7657862c1")

        response = self.vm_image_service.downloadVmImage(request, None)
        with open('image.qcow2', 'ab') as file:
            for res in response:
                print(len(res) / (1024 * 1024))
                file.write(res.content)
