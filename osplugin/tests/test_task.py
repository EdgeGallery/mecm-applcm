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
from core.models import AppInsMapper
from task.app_instance_task import check_stack_status

from tests.resources.test_data import mock_heat_client


class TasksTest(unittest.TestCase):
    """
    定时任务单元测试
    """

    @mock.patch("task.app_instance_task.create_heat_client")
    def test_start_check_instance(self, create_heat_client):
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

        check_stack_status('appIns01')

        with db_session:
            app_ins_info = AppInsMapper.get(app_instance_id='appIns01')
            self.assertEqual(utils.FAILURE, app_ins_info.operational_status)
