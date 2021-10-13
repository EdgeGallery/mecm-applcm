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
import time

from pony.orm import db_session, commit

import utils
from core.log import logger
from core.models import AppInsMapper
from core.openstack_utils import create_heat_client
from task import check_thread_pool

LOG = logger


def start_check_stack_status(app_instance_id):
    """
    start_check_stack_status
    Args:
        app_instance_id:
    """
    check_thread_pool.submit(check_stack_status, app_instance_id)


def check_stack_status(app_instance_id):
    """
    check_stack_status
    Args:
        app_instance_id:
    """
    time.sleep(5)
    try:
        do_check_stack_status(app_instance_id)
    except Exception as exception:
        LOG.error(exception, exc_info=True)


@db_session
def do_check_stack_status(app_instance_id):
    app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
    if not app_ins_mapper:
        LOG.debug('app ins: %s db record not found', app_instance_id)
        return
    heat = create_heat_client(app_ins_mapper.host_ip)
    stack_resp = heat.stacks.get(app_ins_mapper.stack_id)
    if stack_resp is None and app_ins_mapper.operational_status == 'Terminating':
        app_ins_mapper.delete()
        LOG.debug('finish terminate app ins %s', app_instance_id)
        commit()
        return
    if stack_resp.status == 'COMPLETE' or stack_resp.status == 'FAILED':
        LOG.debug('app ins: %s, stack_status: %s, reason: %s',
                  app_instance_id,
                  stack_resp.stack_status,
                  stack_resp.stack_status_reason)
        if stack_resp.stack_status == 'CREATE_COMPLETE':
            app_ins_mapper.operational_status = utils.INSTANTIATED
            app_ins_mapper.operation_info = stack_resp.stack_status_reason
            LOG.debug('finish instantiate app ins %s', app_instance_id)
        elif stack_resp.stack_status == 'DELETE_COMPLETE':
            app_ins_mapper.delete()
            LOG.debug('finish terminate app ins %s', app_instance_id)
        else:
            app_ins_mapper.operation_info = stack_resp.stack_status_reason
            app_ins_mapper.operational_status = utils.FAILURE
            LOG.debug('failed action %s app ins %s', stack_resp.action, app_instance_id)
        commit()
    else:
        LOG.debug('app ins %s status not updated, waite next...')
        start_check_stack_status(app_instance_id)
