# -*- coding: utf-8 -*-
import logging
import os
import threading

from heatclient.exc import HTTPNotFound
from pony.orm import db_session, commit

import utils
from core.models import AppInsMapper
from core.openstack_utils import create_heat_client, RC_FILE_DIR
from internal.lcmservice import lcmservice_pb2_grpc
from internal.lcmservice.lcmservice_pb2 import TerminateResponse, QueryResponse, UploadCfgResponse, RemoveCfgResponse


def get_access_token(stream):
    for request in stream:
        if request.accessToken:
            return request.accessToken
    return None


def get_host_ip(stream):
    for request in stream:
        if request.hostIp:
            return request.hostIp
    return None


def get_upload_config_file(stream):
    for request in stream:
        if request.configFile:
            return request.configFile
    return None


def get_package_data(stream):
    for request in stream:
        if request.package:
            return request.package
    return None


def get_app_instance_id(stream):
    for request in stream:
        if request.appInstanceId:
            return request.appInstanceId
    return None


def start_check_stack_status(app_instance_id, expect_status):
    t = threading.Timer(5, check_stack_status, (app_instance_id, expect_status))
    t.start()


@db_session
def check_stack_status(app_instance_id, expect_status):
    app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
    if not app_ins_mapper:
        return
    heat = create_heat_client(app_ins_mapper.host_ip)
    stack_resp = heat.stacks.get(app_ins_mapper.stack_id)
    if stack_resp is None and expect_status == utils.Terminated:
        app_ins_mapper.delete()
    elif stack_resp is not None and stack_resp.status == 'COMPLETE':
        logging.info('app ins: %s, stack_status: %s, reason: %s',
                     app_instance_id,
                     stack_resp.stack_status,
                     stack_resp.stack_status_reason)
        if stack_resp.status == 'CREATE_COMPLETE':
            app_ins_mapper.operational_status = utils.Instantiated
            app_ins_mapper.operation_info = stack_resp.stack_status_reason
        elif stack_resp.status == 'DELETE_COMPLETE':
            app_ins_mapper.delete()
        else:
            app_ins_mapper.operation_info = stack_resp.stack_status_reason
            app_ins_mapper.operational_status = utils.Failure
    else:
        start_check_stack_status(app_instance_id, expect_status)


def validate_input_params_for_upload_cfg(stream):
    access_token = get_access_token(stream)
    host_ip = get_host_ip(stream)

    if not utils.validate_access_token(access_token):
        return None
    if not utils.validate_ipv4_address(host_ip):
        return None
    return host_ip


class AppLcmService(lcmservice_pb2_grpc.AppLCMServicer):
    @db_session
    def instantiate(self, request_iterator, context):
        pass

    @db_session
    def terminate(self, request, context):
        res = TerminateResponse(status=utils.Failure)
        logging.info('receive terminate msg...')

        host_ip = validate_input_params_for_upload_cfg([request])
        if not host_ip:
            return res

        app_instance_id = get_app_instance_id([request])
        if not app_instance_id:
            return res

        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if not app_ins_mapper:
            res.status = utils.Success
            return res

        heat = create_heat_client(host_ip)
        try:
            heat.stacks.delete(app_ins_mapper.stack_id)
        except HTTPNotFound:
            pass
        except Exception as e:
            logging.error(e)
            return res
        app_ins_mapper.operational_status = utils.Terminating

        commit()
        start_check_stack_status(app_instance_id=app_instance_id, expect_status=utils.Terminated)

        res.status = utils.Success
        return res

    def query(self, request, context):
        logging.info('receive query msg...')
        return QueryResponse(response=utils.Failure)

    def uploadConfig(self, request_iterator, context):
        res = UploadCfgResponse(status=utils.Failure)
        logging.info('receive uploadConfig msg...')

        host_ip = validate_input_params_for_upload_cfg(request_iterator)
        if not host_ip:
            return res

        config_file = get_upload_config_file(request_iterator)
        if not config_file:
            return res

        if not utils.create_dir(RC_FILE_DIR):
            return res

        config_path = RC_FILE_DIR + '/' + host_ip

        try:
            with open(config_path, 'wb') as new_file:
                new_file.write(config_file)
                res.status = utils.Success
        except Exception as e:
            logging.error(e)

        return res

    def removeConfig(self, request, context):
        res = RemoveCfgResponse(status=utils.Failure)
        logging.info('receive removeConfig msg...')

        host_ip = validate_input_params_for_upload_cfg([request])
        if not host_ip:
            return res

        config_path = RC_FILE_DIR + '/' + host_ip
        try:
            os.remove(config_path)
            res.status = utils.Success
        except OSError as e:
            logging.info(e)
            logging.debug('file not exist')
            res.status = utils.Success
        except Exception as e:
            logging.error(e)
            return res

        logging.info('host configuration file deleted successfully')
        return res

    def workloadDescribe(self, request, context):
        pass
