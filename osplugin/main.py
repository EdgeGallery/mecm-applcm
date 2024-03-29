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
from core import grpc_server
from core.log import logger
from task import upload_thread_pool, download_thread_pool, check_thread_pool

if __name__ == "__main__":
    grpc_server.serve()
    upload_thread_pool.shutdown(wait=False)
    logger.info('upload thread pool shutdown')
    download_thread_pool.shutdown(wait=False)
    logger.info('download thread pool shutdown')
    check_thread_pool.shutdown(wait=False)
    logger.info('check thread pool shutdown')
