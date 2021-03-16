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
import unittest

import utils
from core.log import logger
from internal.lcmservice import lcmservice_pb2
from service.app_lcm_service import AppLcmService
from tests import gen_token

LOG = logger


class AppLcmServiceTest(unittest.TestCase):
    app_lcm_service = AppLcmService()
    access_token = gen_token.test_access_token
    host_ip = '159.138.23.91'

    def test_upload_package(self):
        with open('tests/resources/ht-package.zip', 'rb') as f:
            package_data = f.read()
        data = [
            lcmservice_pb2.UploadPackageRequest(accessToken=self.access_token),
            lcmservice_pb2.UploadPackageRequest(hostIp=self.host_ip),
            lcmservice_pb2.UploadPackageRequest(tenantId='tenant001'),
            lcmservice_pb2.UploadPackageRequest(appPackageId='pkg001'),
            lcmservice_pb2.UploadPackageRequest(package=package_data)
        ]
        response = self.app_lcm_service.uploadPackage(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_delete_package(self):
        data = lcmservice_pb2.DeletePackageRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId='tenant001',
            appPackageId='pkg001'
        )
        response = self.app_lcm_service.deletePackage(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_instantiate(self):
        data = lcmservice_pb2.InstantiateRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId='tenant001',
            appInstanceId='test001',
            appPackageId='pkg001',
            ak='ak',
            sk='sk',
        )
        response = self.app_lcm_service.instantiate(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_terminate(self):
        data = lcmservice_pb2.TerminateRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appInstanceId='test001'
        )
        response = self.app_lcm_service.terminate(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_query(self):
        data = lcmservice_pb2.QueryRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appInstanceId='test001'
        )
        response = self.app_lcm_service.query(data, None)
        LOG.info(response.response)

    def test_uploadConfig(self):
        data = [
            lcmservice_pb2.UploadCfgRequest(accessToken=self.access_token),
            lcmservice_pb2.UploadCfgRequest(hostIp='10.0.0.1'),
            lcmservice_pb2.UploadCfgRequest(configFile=b'ddddttttdddttt')
        ]
        response = self.app_lcm_service.uploadConfig(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_removeConfig(self):
        data = lcmservice_pb2.RemoveCfgRequest(
            accessToken=self.access_token,
            hostIp='10.0.0.1'
        )
        response = self.app_lcm_service.removeConfig(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_workloadEvents(self):
        data = lcmservice_pb2.WorkloadEventsRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appInstanceId='test001'
        )
        response = self.app_lcm_service.workloadEvents(data, None)
        LOG.info(response.response)
