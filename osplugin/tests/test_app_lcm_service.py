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
import os
import unittest
from unittest import mock

from pony.orm import db_session, commit

import utils
from core.log import logger
from core.models import AppPkgMapper, VmImageInfoMapper, AppInsMapper
from internal.lcmservice import lcmservice_pb2
from service.app_lcm_service import AppLcmService
from tests.resources import gen_token
from tests.resources.test_data import mock_heat_client, mock_glance_client

LOG = logger


class AppLcmServiceTest(unittest.TestCase):
    """
    applcm service方法单元测试
    """
    app_lcm_service = AppLcmService()
    access_token = gen_token.test_access_token
    host_ip = '159.138.23.91'

    @mock.patch("service.app_lcm_service.start_check_package_status")
    @mock.patch("task.image_task.start_check_image_status")
    @mock.patch("task.image_task.http")
    @mock.patch("task.image_task.create_glance_client")
    @mock.patch("core.csar.pkg.get_image_by_name_checksum")
    def test_upload_package(self, get_image_by_name_checksum,
                            create_glance_client,
                            http,
                            start_check_image_status,
                            start_check_package_status):
        """
        测试上传包
        """
        get_image_by_name_checksum.return_value = {'id': 'abc123'}
        create_glance_client.return_value = mock_glance_client
        http.request.return_value = None
        start_check_image_status.return_value = None
        start_check_package_status.return_value = None

        with open('resources/edgegallery_vm_openstack.zip', 'rb') as f:
            package_data = f.read()
        data = [
            lcmservice_pb2.UploadPackageRequest(accessToken=self.access_token),
            lcmservice_pb2.UploadPackageRequest(hostIp=self.host_ip),
            lcmservice_pb2.UploadPackageRequest(tenantId='tenant001'),
            lcmservice_pb2.UploadPackageRequest(appPackageId='pkg002'),
            lcmservice_pb2.UploadPackageRequest(package=package_data)
        ]
        response = self.app_lcm_service.uploadPackage(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    @mock.patch("service.app_lcm_service.create_glance_client")
    def test_delete_package(self, create_glance_client):
        """
        测试删除包
        """
        with db_session:
            AppPkgMapper(
                app_package_id='pkg001',
                host_ip=self.host_ip,
                status='active'
            )
            VmImageInfoMapper(
                image_id='image001',
                host_ip=self.host_ip,
                image_name='image001',
                status='active',
                app_package_id='pkg001',
                image_size=1024,
                checksum='2'
            )
            commit()

        create_glance_client.return_value = mock_glance_client

        data = lcmservice_pb2.DeletePackageRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId='tenant001',
            appPackageId='pkg001'
        )
        response = self.app_lcm_service.deletePackage(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    @mock.patch('service.app_lcm_service.start_check_stack_status')
    @mock.patch('service.app_lcm_service.create_heat_client')
    @mock.patch("service.app_lcm_service.get_hot_yaml_path")
    def test_instantiate(self, get_hot_yaml_path,
                         create_heat_client,
                         start_check_stack_status):
        """
        测试实例化
        """
        with db_session:
            AppPkgMapper(
                app_package_id='pkg001',
                host_ip=self.host_ip,
                status='active'
            )
            commit()
        get_hot_yaml_path.return_value = 'resources/test_hot.yaml'
        create_heat_client.return_value = mock_heat_client
        start_check_stack_status.return_value = None
        data = lcmservice_pb2.InstantiateRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId='tenant001',
            appInstanceId='test001',
            appPackageId='pkg001',
            parameters = {
                'ak': 'ak',
                'sk': 'sk'
            }
        )
        response = self.app_lcm_service.instantiate(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    @mock.patch('service.app_lcm_service.start_check_stack_status')
    @mock.patch('service.app_lcm_service.create_heat_client')
    def test_terminate(self, create_heat_client, start_check_stack_status):
        """
        测试销毁
        """
        create_heat_client.return_value = mock_heat_client
        start_check_stack_status.return_value = None
        with db_session:
            AppInsMapper(
                app_instance_id='testterminate001',
                host_ip=self.host_ip,
                stack_id='stackterminate001',
                operational_status='Instantiated',
                operation_info=None
            )
            commit()

        data = lcmservice_pb2.TerminateRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appInstanceId='testterminate001'
        )
        response = self.app_lcm_service.terminate(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    @mock.patch('service.app_lcm_service.create_heat_client')
    def test_query(self, create_heat_client):
        """
        测试查询
        """
        with db_session:
            AppInsMapper(
                app_instance_id='25e32a5c-e00f-4edf-b42d-6dd4b610c2db',
                host_ip=self.host_ip,
                stack_id='stacuquery001',
                operational_status='Instantiated',
                operation_info=None
            )
        create_heat_client.return_value = mock_heat_client

        data = lcmservice_pb2.QueryRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appInstanceId='25e32a5c-e00f-4edf-b42d-6dd4b610c2db'
        )
        response = self.app_lcm_service.query(data, None)
        LOG.info(response.response)

    def test_upload_config(self):
        """
        测试上传配置
        """
        if not os.path.exists('target/config'):
            os.mkdir('target/config')

        with open('resources/test_config.rc', 'rb') as f:
            config_file = f.read()
        data = [
            lcmservice_pb2.UploadCfgRequest(accessToken=self.access_token),
            lcmservice_pb2.UploadCfgRequest(hostIp='10.0.0.1'),
            lcmservice_pb2.UploadCfgRequest(configFile=config_file)
        ]
        response = self.app_lcm_service.uploadConfig(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_remove_config(self):
        """
        测试删除配置
        """
        data = lcmservice_pb2.RemoveCfgRequest(
            accessToken=self.access_token,
            hostIp='10.0.0.1'
        )
        response = self.app_lcm_service.removeConfig(data, None)
        self.assertEqual(response.status, utils.SUCCESS)

    @mock.patch('service.app_lcm_service.create_heat_client')
    def test_workload_events(self, create_heat_client):
        """
        测试查询实例化事件
        """
        with db_session:
            AppInsMapper(
                app_instance_id='35e32a5c-e00f-4edf-b42d-6dd4b610c2db',
                host_ip=self.host_ip,
                stack_id='stackevent001',
                operational_status='Instantiated',
                operation_info=None
            )
        create_heat_client.return_value = mock_heat_client

        data = lcmservice_pb2.WorkloadEventsRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appInstanceId='35e32a5c-e00f-4edf-b42d-6dd4b610c2db'
        )
        response = self.app_lcm_service.workloadEvents(data, None)
        LOG.info(response.response)
