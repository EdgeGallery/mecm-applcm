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
from unittest import mock

from pony.orm import db_session, commit
import utils
from config import base_dir
from core.models import AppInsMapper, VmImageInfoMapper, AppPkgMapper
from task.app_instance_task import do_check_stack_status
from task.app_package_task import do_check_package_status
from task.image_task import do_check_image_status, do_download_then_compress_image, do_check_compress_status, \
    do_push_image

from tests.resources.test_data import mock_heat_client, mock_glance_client, MockResponse


class TasksTest(unittest.TestCase):
    """
    定时任务单元测试
    """

    @mock.patch("task.app_instance_task.create_heat_client")
    def test_do_check_stack_status(self, create_heat_client):
        """
        测试检查实例状态任务
        Returns:

        """
        create_heat_client.return_value = mock_heat_client

        with db_session:
            AppInsMapper(
                app_instance_id='appIns01',
                host_ip='10.10.10.10',
                stack_id='stack001',
                operational_status=utils.INSTANTIATING
            )
            commit()

        do_check_stack_status('appIns01')

        with db_session:
            app_ins_info = AppInsMapper.get(app_instance_id='appIns01')
            self.assertEqual(utils.FAILURE, app_ins_info.operational_status)

    @mock.patch('task.image_task.create_glance_client')
    def test_do_check_image_status(self, create_glance_client):
        """

        Args:
            create_glance_client:

        Returns:

        """
        create_glance_client.return_value = mock_glance_client

        with db_session:
            VmImageInfoMapper(
                image_id='test_image',
                host_ip='10.10.10.10',
                image_name='test_image',
                status='queued',
                tenant_id='test_tenant',
                app_package_id='test_package'
            )
            commit()

        do_check_image_status('test_image', '10.10.10.10')

        with db_session:
            image_info = VmImageInfoMapper.get(image_id='test_image', host_ip='10.10.10.10')
            self.assertEqual(utils.ACTIVE, image_info.status)

    @mock.patch('task.image_task.add_check_compress_image_task')
    @mock.patch('task.image_task.requests')
    @mock.patch('task.image_task.create_glance_client')
    def test_do_download_then_compress_image(self, create_glance_client, requests, add_check_compress_image_task):
        """

        Args:
            create_glance_client:

        Returns:

        """
        create_glance_client.return_value = mock_glance_client
        requests.post.return_value = MockResponse({
            'status_code': 200,
            'json': {
                'requestId': 'abcabcabcabc'
            }
        })
        add_check_compress_image_task.return_value = None

        with db_session:
            VmImageInfoMapper(
                image_id='test_image1',
                host_ip='10.10.10.10',
                image_name='test_image1',
                status='downloading',
                tenant_id='test_tenant'
            )
            commit()

        do_download_then_compress_image('test_image1', '10.10.10.10')

        with db_session:
            image_info = VmImageInfoMapper.get(image_id='test_image1', host_ip='10.10.10.10')
            self.assertEqual(utils.COMPRESSING, image_info.status)

    @mock.patch('task.image_task.add_push_image_task')
    @mock.patch('task.image_task.requests')
    def test_do_check_compress_status(self, requests, add_push_image_task):
        """

        Returns:

        """
        requests.get.return_value = MockResponse({
            'status_code': 200,
            'json': {
                'status': 0
            }
        })
        add_push_image_task.return_value = None

        with db_session:
            VmImageInfoMapper(
                image_id='test_image2',
                host_ip='10.10.10.10',
                image_name='test_image2',
                status='compressing',
                tenant_id='test_tenant'
            )
            commit()

        do_check_compress_status('test_image2', '10.10.10.10')

        with db_session:
            image_info = VmImageInfoMapper.get(image_id='test_image2', host_ip='10.10.10.10')
            self.assertEqual(utils.PUSHING, image_info.status)

        utils.delete_dir(f'{base_dir}/vmImage')

    @mock.patch('task.image_task.requests')
    def test_do_push_image(self, requests):
        requests.post.return_value = MockResponse({
            'status_code': 200,
            'json': {
                'imageId': 'mock_image_id'
            }
        })

        with db_session:
            VmImageInfoMapper(
                image_id='test_image3',
                host_ip='10.10.10.10',
                image_name='test_image3',
                status='pushing',
                tenant_id='test_tenant'
            )
            commit()

        utils.create_dir(f'{base_dir}/vmImage/10.10.10.10')
        with open(f'{base_dir}/vmImage/10.10.10.10/test_image3.qcow2', 'w') as image_file:
            image_file.writelines('abcabcabc')

        do_push_image('test_image3', '10.10.10.10')

        with db_session:
            image_info = VmImageInfoMapper.get(image_id='test_image3', host_ip='10.10.10.10')
            self.assertEqual(utils.ACTIVE, image_info.status)
            self.assertEqual('mock_image_id', image_info.compress_task_id)

        utils.delete_dir(f'{base_dir}/vmImage')

    @mock.patch('task.app_package_task.start_check_package_status')
    def test_do_check_package_status(self, start_check_package_status):
        start_check_package_status.return_value = None

        with db_session:
            AppPkgMapper(
                app_package_id='app_package_id1',
                host_ip='10.10.10.10',
                status='uploading'
            )
            VmImageInfoMapper(
                image_id='image_id1',
                image_name='image_name1',
                app_package_id='app_package_id1',
                host_ip='10.10.10.10',
                status='active'
            )
            VmImageInfoMapper(
                image_id='image_id2',
                image_name='image_name2',
                app_package_id='app_package_id1',
                host_ip='10.10.10.10',
                status='active'
            )
            commit()

        do_check_package_status('app_package_id1', '10.10.10.10')

        with db_session:
            app_package_info = AppPkgMapper.get(app_package_id='app_package_id1', host_ip='10.10.10.10')
            self.assertEqual(utils.UPLOADED, app_package_info.status)
