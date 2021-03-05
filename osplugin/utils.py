# -*- coding: utf-8 -*-

import os
import re
import uuid

import jwt
import logging

from config import jwt_public_key

Failure = 'Failure'
Success = 'Success'

Instantiating = 'Instantiating'
Instantiated = 'Instantiated'
Terminated = 'Terminated'
Terminating = 'Terminating'


def create_dir(path):
    try:
        os.makedirs(path)
    except OSError:
        logging.debug('文件加已存在')
    except Exception as e:
        logging.error(e)
        return False
    return True


def delete_dir(path):
    for i in os.listdir(path):
        file_data = path + '/' + i
        if os.path.isfile(file_data):
            os.remove(file_data)
        else:
            delete_dir(file_data)
    os.rmdir(path)


def validate_access_token(access_token):
    if not access_token:
        logging.info('accessToken required')
        return False
    try:
        payload = jwt.decode(access_token, jwt_public_key, algorithms=['RS256'])
        if not payload['authorities']:
            logging.info('Invalid token A')
            return False
        if not payload['userId']:
            logging.info('Invalid token UI')
            return False
        if not payload['user_name']:
            logging.info('Invalid token UN')
            return False
    except Exception as e:
        logging.error(e)
        return False
    return True


def validate_ipv4_address(host_ip):
    if not host_ip:
        logging.info('hostIp required')
        return False
    p = re.compile('^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    if p.match(host_ip):
        return True
    else:
        return False


def gen_uuid():
    return ''.join(str(uuid.uuid4()).split('-'))
