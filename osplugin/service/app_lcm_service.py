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
from internal.lcmservice.lcmservice_pb2 import TerminateResponse, \
    QueryResponse, UploadCfgResponse, RemoveCfgResponse

_APP_TMP_PATH = config.base_dir + '/tmp'


def start_check_stack_status(app_instance_id):
    """
    start_check_stack_status
    Args:
        app_instance_id:
    """
    thread_timer = threading.Timer(5, check_stack_status, app_instance_id)
    thread_timer.start()


@db_session
def check_stack_status(app_instance_id):
    """
    check_stack_status
    Args:
        app_instance_id:
    """
    app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
    if not app_ins_mapper:
        return
    heat = create_heat_client(app_ins_mapper.host_ip)
    stack_resp = heat.stacks.get(app_ins_mapper.stack_id)
    if stack_resp is None and app_ins_mapper.operational_status == 'Terminating':
        app_ins_mapper.delete()
        return
    if stack_resp.status == 'COMPLETE' or stack_resp.status == 'FAILED':
        logging.info('app ins: %s, stack_status: %s, reason: %s',
                     app_instance_id,
                     stack_resp.stack_status,
                     stack_resp.stack_status_reason)
        if stack_resp.action == 'CREATE' and stack_resp.stack_status == 'CREATE_COMPLETE':
            app_ins_mapper.operational_status = utils.INSTANTIATED
            app_ins_mapper.operation_info = stack_resp.stack_status_reason
        elif stack_resp.action == 'DELETE' and stack_resp.stack_status == 'DELETE_COMPLETE':
            app_ins_mapper.delete()
        else:
            app_ins_mapper.operation_info = stack_resp.stack_status_reason
            app_ins_mapper.operational_status = utils.FAILURE
    else:
        start_check_stack_status(app_instance_id)


def validate_input_params(param):
    """
    check_stack_status
    Args:
        param:
    Returns:
        host_ip
    """
    access_token = param.accessToken
    host_ip = param.hostIp
    if not utils.validate_access_token(access_token):
        return None
    if not utils.validate_ipv4_address(host_ip):
        return None
    return host_ip


class AppLcmService(lcmservice_pb2_grpc.AppLCMServicer):
    """
    AppLcmService
    """

    @db_session
    def instantiate(self, request_iterator, context):
        logging.debug('receive instantiate msg...')
        res = TerminateResponse(status=utils.FAILURE)

        parameter = InstantiateRequest(request_iterator)
        logging.debug('parameters: %s', parameter)

        host_ip = validate_input_params(parameter)
        if not host_ip:
            return res

        app_instance_id = parameter.app_instance_id
        if not app_instance_id:
            return res

        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        logging.debug('db data %s', app_ins_mapper)
        if app_ins_mapper is not None:
            logging.info('app ins %s exist', app_instance_id)
            return res

        if parameter.app_package_path is None:
            logging.info('app package data is none')
            return res

        logging.debug('writing package file')
        app_ins_tmp_path = _APP_TMP_PATH + '/instance/' + app_instance_id
        utils.create_dir(app_ins_tmp_path)

        try:
            logging.debug('unzip package')
            with zipfile.ZipFile(parameter.app_package_path) as zip_file:
                namelist = zip_file.namelist()
                for f in namelist:
                    zip_file.extract(f, app_ins_tmp_path)
            parameter.delete_package_tmp()
        except Exception as e:
            logging.error(e)
            parameter.delete_package_tmp()
            utils.delete_dir(app_ins_tmp_path)
            return res

        hot_yaml_path = get_hot_yaml_path(app_ins_tmp_path)
        logging.debug('hot template path %s', hot_yaml_path)
        tpl_files, template = template_utils.get_template_contents(template_file=hot_yaml_path)
        fields = {
            'stack_name': 'eg-' + ''.join(str(uuid.uuid4()).split('-'))[0:8],
            'template': template,
            'files': dict(list(tpl_files.items()))
        }
        logging.debug('init heat client')
        heat = create_heat_client(host_ip)
        try:
            stack_resp = heat.stacks.create(**fields)
            utils.delete_dir(app_ins_tmp_path)
        except Exception as e:
            logging.error(e)
            utils.delete_dir(app_ins_tmp_path)
            return res
        AppInsMapper(app_instance_id=app_instance_id,
                     host_ip=host_ip,
                     stack_id=stack_resp['stack']['id'],
                     operational_status=utils.INSTANTIATING)
        commit()

        start_check_stack_status(app_instance_id=app_instance_id)

        res.status = utils.SUCCESS
        return res

    @db_session
    def terminate(self, request, context):
        logging.info('receive terminate msg...')
        res = TerminateResponse(status=utils.FAILURE)

        host_ip = validate_input_params(request)
        if not host_ip:
            return res

        app_instance_id = request.appInstanceId
        if not app_instance_id:
            return res

        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if not app_ins_mapper:
            res.status = utils.SUCCESS
            return res

        heat = create_heat_client(host_ip)
        try:
            heat.stacks.delete(app_ins_mapper.stack_id)
        except HTTPNotFound:
            pass
        except Exception as e:
            logging.error(e)
            return res
        app_ins_mapper.operational_status = utils.TERMINATING

        commit()
        start_check_stack_status(app_instance_id=app_instance_id)

        res.status = utils.SUCCESS
        return res

    def query(self, request, context):
        logging.info('receive query msg...')
        res = QueryResponse(response='{"code": 500, "msg": "server error"}')

        host_ip = validate_input_params(request)
        if not host_ip:
            return res

        app_instance_id = request.appInstanceId
        if not app_instance_id:
            return res

        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if not app_ins_mapper:
            return res

        heat = create_heat_client(host_ip)
        output_list = heat.stacks.output_list(app_ins_mapper.stack_id)

        response = {
            'code': 200,
            'msg': 'ok',
            'data': []
        }
        for key, value in output_list.items():
            item = {
                'vmId': value['vmId'],
                'vncUrl': value['vncUrl'],
                'networks': []
            }
            for net_name, ip_data in value['networks']:
                if utils.validate_uuid(net_name):
                    continue
                network = {
                    'name': net_name,
                    'ip': ip_data['addr']
                }
                item['networks'].append(network)
            response['data'].append(item)

        res.response = json.dumps(response)
        return res

    def uploadConfig(self, request_iterator, context):
        logging.info('receive uploadConfig msg...')
        res = UploadCfgResponse(status=utils.FAILURE)

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
                res.status = utils.SUCCESS
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
        res = RemoveCfgResponse(status=utils.FAILURE)

        host_ip = validate_input_params(request)
        if not host_ip:
            return res

        config_path = RC_FILE_DIR + '/' + host_ip
        try:
            os.remove(config_path)
            res.status = utils.SUCCESS
        except OSError as e:
            logging.info(e)
            logging.debug('file not exist')
            res.status = utils.SUCCESS
        except Exception as e:
            logging.error(e)
            return res

        logging.info('host configuration file deleted successfully')
        return res

    def workloadEvents(self, request, context):
        logging.info('receive workload describe msg...')
        res = TerminateResponse(status=utils.FAILURE)

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
        res.response = json.dumps(events)
        return res
