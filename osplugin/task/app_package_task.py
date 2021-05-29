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
from core.models import VmImageInfoMapper, AppPkgMapper
from task import check_thread_pool


def start_check_package_status(package_id, host_ip):
    """

    Args:
        package_id:
        host_ip:

    Returns:

    """
    check_thread_pool.submit(_check_package_status, package_id, host_ip)


@db_session
def _check_package_status(package_id, host_ip):
    time.sleep(5)
    try:
        package = AppPkgMapper.get(app_package_id=package_id, host_ip=host_ip)
        if package is None:
            return
        image_infos = VmImageInfoMapper.select(app_package_id=package_id, host_ip=host_ip)
    except Exception as exception:
        logger.error(exception, exc_info=True)
        return
    for image_info in image_infos:
        if image_info.status != utils.ACTIVE:
            if image_info.status == utils.KILLED:
                package.status = utils.FAILURE
            else:
                package.status = utils.SAVING
                start_check_package_status(package_id, host_ip)
            commit()
            return
    package.status = utils.ACTIVE
    commit()
