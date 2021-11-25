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
from concurrent import futures

import grpc

import config
from core.log import logger
from internal.lcmservice import lcmservice_pb2_grpc
from internal.resourcemanager import resourcemanager_pb2_grpc
from service.app_lcm_service import AppLcmService
from service.flavor_service import FlavorService
from service.network_service import NetworkService
from service.security_group_service import SecurityGroupService
from service.vm_service import VmService
from service.image_service import ImageService

LISTEN_PORT = 8234
MAX_MESSAGE_LENGTH = 1024 * 1024 * 4
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
    resourcemanager_pb2_grpc.add_VmManagerServicer_to_server(VmService(), server)
    resourcemanager_pb2_grpc.add_VmImageMangerServicer_to_server(ImageService(), server)
    resourcemanager_pb2_grpc.add_FlavorManagerServicer_to_server(FlavorService(), server)
    resourcemanager_pb2_grpc.add_NetworkManagerServicer_to_server(NetworkService(), server)
    resourcemanager_pb2_grpc.add_SecurityGroupManagerServicer_to_server(SecurityGroupService(), server)

    listen_addr = config.listen_ip + ":" + str(LISTEN_PORT)

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
        LOG.info('Server stopped')
