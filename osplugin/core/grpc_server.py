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

from concurrent import futures

# -*- coding: utf-8 -*-
import grpc

import config
from core.log import logger
from internal.lcmservice import lcmservice_pb2_grpc
from service.app_lcm_service import AppLcmService
from service.vm_image_service import VmImageService
from task import upload_thread_pool

_ONE_DAY_IN_SECONDS = 60 * 60 * 24
_LISTEN_PORT = 8234
MAX_MESSAGE_LENGTH = 1024 * 1024 * 50
LOG = logger


def serve():
    """
    启动grpc服务
    """
    options = [
        ('grpc.max_send_message_length', MAX_MESSAGE_LENGTH),
        ('grpc.max_receive_message_length', MAX_MESSAGE_LENGTH),
    ]

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=200, thread_name_prefix='HandlerExecutor'),
        options=options
    )
    lcmservice_pb2_grpc.add_AppLCMServicer_to_server(AppLcmService(), server)
    lcmservice_pb2_grpc.add_VmImageServicer_to_server(VmImageService(), server)

    listen_addr = config.listen_ip + ":" + str(_LISTEN_PORT)

    if config.ssl_enabled:
        with open(config.private_key_certificate_chain_pairs[0], 'rb') as file:
            private_key = file.read()
        with open(config.private_key_certificate_chain_pairs[1], 'rb') as file:
            certificate_chain = file.read()
        with open(config.root_certificates, 'rb') as file:
            root_certificates = file.read()
        cert_config = grpc.ssl_server_credentials(
            private_key_certificate_chain_pairs=((private_key, certificate_chain), ),
            root_certificates=root_certificates,
            require_client_auth=False
        )
        server.add_secure_port(listen_addr, cert_config)
    else:
        server.add_insecure_port(listen_addr)

    try:
        server.start()
        LOG.info("Started server on %s", listen_addr)
        server.wait_for_termination()
    except KeyboardInterrupt:
        upload_thread_pool.shutdown()
        LOG.info('Server stopped')
