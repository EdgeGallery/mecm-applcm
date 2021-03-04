# -*- coding: utf-8 -*-
import grpc
import config
import logging
from concurrent import futures
from internal.lcmservice import lcmservice_pb2_grpc
from service.app_lcm_service import AppLcmService
from service.vm_image_service import VmImageService

_ONE_DAY_IN_SECONDS = 60 * 60 * 24
_LISTEN_PORT = 8234


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=200, thread_name_prefix='grpc-thread-'))
    lcmservice_pb2_grpc.add_AppLCMServicer_to_server(AppLcmService(), server)
    lcmservice_pb2_grpc.add_VmImageServicer_to_server(VmImageService(), server)

    listen_addr = config.listen_ip + ":" + str(_LISTEN_PORT)

    if config.enable_ssl:
        cert_config = grpc.ssl_server_credentials(
            private_key_certificate_chain_pairs=config.private_key_certificate_chain_pairs,
            root_certificates=config.root_certificates,
            require_client_auth=config.require_client_auth
        )
        server.add_secure_port(listen_addr, cert_config)
    else:
        server.add_insecure_port(listen_addr)

    server.start()
    logging.info("Starting server on %s", listen_addr)
    server.wait_for_termination()
    logging.info('Server stopped')
