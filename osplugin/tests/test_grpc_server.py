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

import logging
import unittest

import grpc

from internal.lcmservice import lcmservice_pb2_grpc, lcmservice_pb2
from tests import gen_token

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = \
    logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)


def _get_secure_channel(options):
    """
    获取ssl通道
    """
    with open('../target/ssl/server_tls.crt', 'rb') as file:
        root_certificates = file.read()
    credentials = grpc.ssl_channel_credentials(root_certificates=root_certificates)
    return grpc.secure_channel(target='mecm-mepm-osplugin:38234',
                               credentials=credentials, options=options)


class GrpcServerTest(unittest.TestCase):
    """
    grpc客户端
    """
    access_token = gen_token.test_access_token
    host_ip = '192.168.1.110'

    def __init__(self, method_name='runTest'):
        super().__init__(method_name)
        options = [
            ('grpc.ssl_target_name_override', 'edgegallery.org',),
            ('grpc.max_send_message_length', 50 * 1024 * 1024),
            ('grpc.max_receive_message_length', 50 * 1024 * 1024)]
        # channel = _get_secure_channel(options)
        channel = grpc.insecure_channel(target='127.0.0.1:8234', options=options)
        """
        channel = grpc.insecure_channel(target='127.0.0.1:8234', options=options)
        """
        self.app_lcm_stub = lcmservice_pb2_grpc.AppLCMStub(channel)
        self.vm_image_stub = lcmservice_pb2_grpc.VmImageStub(channel)

    def test_create_image(self):
        """
        测试创建镜像
        """
        request = lcmservice_pb2.CreateVmImageRequest(
            accessToken=self.access_token,
            appInstanceId='ins001',
            hostIp=self.host_ip,
            vmId='caf83c05-56dc-4f7c-b417-40d9acbf166c'
        )
        response = self.vm_image_stub.createVmImage(request)
        self.assertEqual(response.response, 'Success')

    def test_upload_package(self):
        """
        测试上传包
        """
        with open('resources/simple-package.zip', 'rb') as file:
            package = file.read()
        request = iter([
            lcmservice_pb2.UploadPackageRequest(accessToken=self.access_token),
            lcmservice_pb2.UploadPackageRequest(hostIp='159.138.57.166'),
            lcmservice_pb2.UploadPackageRequest(appPackageId='pkg001'),
            lcmservice_pb2.UploadPackageRequest(tenantId='tenant001'),
            lcmservice_pb2.UploadPackageRequest(package=package)
        ])
        response = self.app_lcm_stub.uploadPackage(request)
        self.assertEqual(response.status, 'Success')

    def test_delete_package(self):
        """
        测试删除包
        """
        request = lcmservice_pb2.DeletePackageRequest(
            accessToken=self.access_token,
            hostIp='159.138.57.166',
            appPackageId='pkg001',
            tenantId='tenant001',
        )
        response = self.app_lcm_stub.deletePackage(request)
        self.assertEqual(response.status, 'Success')

    def test_upload_cfg(self):
        """
        测试上传配置
        """
        with open('resources/10.10.10.10', 'rb') as file:
            data = file.read()
        request = iter([
            lcmservice_pb2.UploadCfgRequest(accessToken=self.access_token),
            lcmservice_pb2.UploadCfgRequest(hostIp='10.10.10.10'),
            lcmservice_pb2.UploadCfgRequest(configFile=data)
        ])
        response = self.app_lcm_stub.uploadConfig(request)
        self.assertEqual(response.status, 'Success')

    def test_delete_cfg(self):
        """
        测试删除配置
        """
        request = lcmservice_pb2.RemoveCfgRequest(
            accessToken=self.access_token,
            hostIp='10.10.10.10'
        )
        response = self.app_lcm_stub.removeConfig(request)
        self.assertEqual(response.status, 'Success')

    def test_instantiate(self):
        """
        测试实例化
        """
        request = lcmservice_pb2.InstantiateRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appInstanceId='ins001',
            appPackageId='pkg001',
            tenantId='tenant001',
            ak='ak001',
            sk='sk001'
        )
        response = self.app_lcm_stub.instantiate(request)
        self.assertEqual(response.status, 'Success')

    def test_terminate(self):
        """
        测试销毁实例
        """
        request = lcmservice_pb2.TerminateRequest(
            accessToken=self.access_token,
            appInstanceId='ins001',
            hostIp=self.host_ip,
        )
        response = self.app_lcm_stub.terminate(request)
        self.assertEqual(response.status, 'Success')

    def test_query(self):
        """
        测试获取实例信息
        """
        request = lcmservice_pb2.QueryRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appInstanceId='ins001',
        )
        response = self.app_lcm_stub.query(request)
        print(response.response)

    def test_query_image(self):
        """
        测试查询镜像信息
        """
        request = lcmservice_pb2.QueryVmImageRequest(
            accessToken=self.access_token,
            appInstanceId='app_instance_id',
            hostIp=self.host_ip,
            imageId='79414ac9-610b-4243-90f6-e830e2e7d97c'
        )

        response = self.vm_image_stub.queryVmImage(request)
        logger.info(response.response)

    def test_download_image(self):
        """
        测试下载镜像
        """
        receive_size = 0
        with open('../target/image.qcow2', 'wb') as file:
            request = lcmservice_pb2\
                .DownloadVmImageRequest(accessToken=self.access_token,
                                        hostIp=self.host_ip,
                                        appInstanceId='app_instance_id',
                                        imageId='887731bd-3ffc-4f6b-a9f1-962d4fd6276b')
            response = self.vm_image_stub.downloadVmImage(request)
            for res in response:
                receive_size += len(res.content)
                logger.info('receive size %s' % receive_size)
                file.write(res.content)
