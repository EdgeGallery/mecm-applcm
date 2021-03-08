# -*- coding: utf-8 -*-
import json
import logging
import os
import threading
import uuid
import zipfile

from heatclient.common import template_utils
from heatclient.exc import HTTPNotFound
from pony.orm import db_session, commit

import config
import utils
from core.csar.pkg import get_hot_yaml_path
from core.models import AppInsMapper, InstantiateRequest, UploadCfgRequest
from core.openstack_utils import create_heat_client, RC_FILE_DIR
from internal.lcmservice import lcmservice_pb2_grpc
from internal.lcmservice.lcmservice_pb2 import TerminateResponse, QueryResponse, UploadCfgResponse, RemoveCfgResponse

_APP_TMP_PATH = config.base_dir + '/tmp'


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


def validate_input_params(param):
    access_token = param.accessToken
    host_ip = param.hostIp
    # if not utils.validate_access_token(access_token):
    #     return None
    if not utils.validate_ipv4_address(host_ip):
        return None
    return host_ip


class AppLcmService(lcmservice_pb2_grpc.AppLCMServicer):
    @db_session
    def instantiate(self, request_iterator, context):
        logging.info('receive instantiate msg...')
        res = TerminateResponse(status=utils.Failure)

        parameter = InstantiateRequest(request_iterator)

        host_ip = validate_input_params(parameter)
        if not host_ip:
            return res

        app_instance_id = parameter.app_instance_id
        if not app_instance_id:
            return res

        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if app_ins_mapper is not None:
            logging.info('app ins %s exist', app_instance_id)
            return res

        if parameter.app_package_path is None:
            logging.info('app package data is none')
            return res

        app_ins_tmp_path = _APP_TMP_PATH + '/instance/' + app_instance_id
        utils.create_dir(app_ins_tmp_path)

        try:
            with zipfile.ZipFile(parameter.app_package_path) as zip_file:
                namelist = zip_file.namelist()
                for f in namelist:
                    zip_file.extract(f, app_ins_tmp_path)
        except Exception as e:
            logging.error(e)
            parameter.delete_package_tmp()
            utils.delete_dir(app_ins_tmp_path)
            return res

        parameter.delete_package_tmp()
        hot_yaml_path = get_hot_yaml_path(app_ins_tmp_path)
        """
        """
        tpl_files, template = template_utils.get_template_contents(template_file=hot_yaml_path)
        fields = {
            'stack_name': 'eg-' + ''.join(str(uuid.uuid4()).split('-'))[0:8],
            'template': template,
            'files': dict(list(tpl_files.items()))
        }
        heat = create_heat_client(host_ip)
        try:
            stack_resp = heat.stacks.create(**fields)
        except Exception as e:
            logging.error(e)
            utils.delete_dir(app_ins_tmp_path)
            return res
        AppInsMapper(app_instance_id=app_instance_id,
                     host_ip=host_ip,
                     stack_id=stack_resp['stack']['id'],
                     operational_status=utils.Instantiating)
        commit()

        start_check_stack_status(app_instance_id=app_instance_id, expect_status='COMPLETE')

        utils.delete_dir(app_ins_tmp_path)

        res.status = utils.Success
        return res

    @db_session
    def terminate(self, request, context):
        logging.info('receive terminate msg...')
        res = TerminateResponse(status=utils.Failure)

        host_ip = validate_input_params(request)
        if not host_ip:
            return res

        app_instance_id = request.appInstanceId
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
        res = QueryResponse(response='{"code": 500, "msg": "server error"}')

        host_ip = validate_input_params(request)
        if not host_ip:
            return res

        res.response = '{"code": 200, "msg": "ok"}'
        return res

    def uploadConfig(self, request_iterator, context):
        logging.info('receive uploadConfig msg...')
        res = UploadCfgResponse(status=utils.Failure)

        parameter = UploadCfgRequest(request_iterator)

        host_ip = validate_input_params(parameter)
        if not host_ip:
            return res

        config_file = parameter.config_file
        if config_file is None:
            return res

        if utils.create_dir(RC_FILE_DIR) is None:
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
        """
        删除openstack 配置文件
        :param request: 请求体
        :param context: 上下文信息
        :return: Success/Failure
        """
        logging.info('receive removeConfig msg...')
        res = RemoveCfgResponse(status=utils.Failure)

        host_ip = validate_input_params(request)
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
        logging.info('receive workload describe msg...')
        res = TerminateResponse(status=utils.Failure)

        host_ip = validate_input_params(request)
        if not host_ip:
            return res

        app_instance_id = request.appInstanceId
        if not app_instance_id:
            return res

        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if not app_ins_mapper:
            logging.info('app实例 %s 不存在', app_instance_id)
            return res

        heat = create_heat_client(host_ip)

        events = heat.events.list(stack_id=app_ins_mapper.stack_id)
        res.status = json.dumps(events)
        return res