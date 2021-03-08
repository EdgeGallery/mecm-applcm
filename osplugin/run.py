#!python3
# -*- coding: utf-8 -*-
import logging

from core import grpc_server

_LOGGING_FORMAT = '%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s'


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=_LOGGING_FORMAT)
    grpc_server.serve()