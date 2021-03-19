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
import os
import threading
import uuid
import zipfile

from heatclient.common import template_utils
from heatclient.exc import HTTPNotFound
from pony.orm import db_session, commit

import utils
from core.csar.pkg import get_hot_yaml_path, CsarPkg
from core.log import logger
from core.models import AppInsMapper, InstantiateRequest, UploadCfgRequest, UploadPackageRequest
from core.openstack_utils import create_heat_client
from internal.lcmservice import lcmservice_pb2_grpc
from internal.lcmservice.lcmservice_pb2 import TerminateResponse, \
    QueryResponse, UploadCfgResponse, RemoveCfgResponse, DeletePackageResponse, UploadPackageResponse, \
    WorkloadEventsResponse

LOG = logger


def start_check_stack_status(app_instance_id):
    """
    start_check_stack_status
    Args:
        app_instance_id:
    """
    thread_timer = threading.Timer(5, check_stack_status, [app_instance_id])
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
        LOG.debug('app ins: %s, stack_status: %s, reason: %s',
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
    LOG.debug('param hostIp: %s', host_ip)
    LOG.debug('param accessToken: %s', access_token)
    if not utils.validate_access_token(access_token):
        return None
    if not utils.validate_ipv4_address(host_ip):
        return None
    return host_ip


class AppLcmService(lcmservice_pb2_grpc.AppLCMServicer):
    """
    AppLcmService
    """
    def uploadPackage(self, request_iterator, context):
        """
        上传app包
        :param request_iterator:
        :param context:
        :return:
        """
        LOG.debug('receive upload package msg...')
        res = UploadPackageResponse(status=utils.FAILURE)

        parameters = UploadPackageRequest(request_iterator)

        host_ip = validate_input_params(parameters)
        if host_ip is None:
            parameters.delete_tmp()
            return res

        # TODO: 预加载镜像

        app_package_id = parameters.app_package_id
        if app_package_id is None:
            LOG.info('appPackageId is required')
            parameters.delete_tmp()
            return res
        app_package_path = utils.APP_PACKAGE_DIR + '/' + host_ip + '/' + parameters.app_package_id
        if utils.exists_path(app_package_path):
            LOG.info('app package exist')
            parameters.delete_tmp()
            return res
        utils.create_dir(app_package_path)
        try:
            LOG.debug('unzip package')
            with zipfile.ZipFile(parameters.tmp_package_file_path) as zip_file:
                namelist = zip_file.namelist()
                for f in namelist:
                    zip_file.extract(f, app_package_path)
            pkg = CsarPkg(app_package_path)
            pkg.translate()
            res.status = utils.SUCCESS
        except Exception as e:
            LOG.error(e, exc_info=True)
            utils.delete_dir(app_package_path)
        finally:
            parameters.delete_tmp()
            return res

    def deletePackage(self, request, context):
        """
        删除app包
        :param request:
        :param context:
        :return:
        """
        LOG.debug('receive delete package msg...')
        res = DeletePackageResponse(status=utils.FAILURE)

        host_ip = validate_input_params(request)
        if host_ip is None:
            return res

        app_package_id = request.appPackageId
        if not app_package_id:
            return res

        # TODO: 销毁加载的镜像

        app_package_path = utils.APP_PACKAGE_DIR + '/' + host_ip + '/' + app_package_id
        utils.delete_dir(app_package_path)

        res.status = utils.SUCCESS
        return res

    @db_session
    def instantiate(self, request, context):
        """
        app 实例化
        :param request:
        :param context:
        :return:
        """
        req_id = utils.gen_uuid()
        LOG.debug('%s: receive instantiate msg...', req_id)
        res = TerminateResponse(status=utils.FAILURE)

        parameter = InstantiateRequest(request)

        LOG.debug('%s: 校验access token, host ip', req_id)
        host_ip = validate_input_params(parameter)
        if host_ip is None:
            return res

        LOG.debug('%s: 获取实例ID', req_id)
        app_instance_id = parameter.app_instance_id
        if app_instance_id is None:
            return res

        LOG.debug('%s: 查询数据库是否存在相同记录', req_id)
        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if app_ins_mapper is not None:
            LOG.info('app ins %s exist', app_instance_id)
            return res

        LOG.debug('%s: 读取包的hot文件', req_id)
        hot_yaml_path = get_hot_yaml_path(parameter.app_package_path)
        if hot_yaml_path is None:
            return res

        LOG.debug('%s: 构建heat参数', req_id)
        tpl_files, template = template_utils.get_template_contents(template_file=hot_yaml_path)
        fields = {
            'stack_name': 'eg-' + ''.join(str(uuid.uuid4()).split('-'))[0:8],
            'template': template,
            'files': dict(list(tpl_files.items()))
        }
        LOG.debug('%s: init heat client', req_id)
        heat = create_heat_client(host_ip)
        try:
            LOG.debug('%s: 发送创建stack请求', req_id)
            stack_resp = heat.stacks.create(**fields)
        except Exception as e:
            LOG.error(e, exc_info=True)
            return res
        AppInsMapper(app_instance_id=app_instance_id,
                     host_ip=host_ip,
                     stack_id=stack_resp['stack']['id'],
                     operational_status=utils.INSTANTIATING)
        LOG.debug('%s: 更新数据库', req_id)
        commit()

        LOG.debug('%s: 开始更新状态定时任务', req_id)
        start_check_stack_status(app_instance_id=app_instance_id)

        res.status = utils.SUCCESS
        LOG.debug('%s: 消息处理完成', req_id)
        return res

    @db_session
    def terminate(self, request, context):
        """
        销毁实例
        :param request:
        :param context:
        :return:
        """
        req_id = utils.gen_uuid()
        LOG.debug('%s: receive terminate msg...', req_id)
        res = TerminateResponse(status=utils.FAILURE)

        LOG.debug('%s: 校验token, host ip', req_id)
        host_ip = validate_input_params(request)
        if host_ip is None:
            return res

        LOG.debug('%s: 获取实例ID', req_id)
        app_instance_id = request.appInstanceId
        if app_instance_id is None:
            return res

        LOG.debug('%s: 查询数据库', req_id)
        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if app_ins_mapper is None:
            res.status = utils.SUCCESS
            return res

        LOG.debug('%s: 初始化openstack客户端', req_id)
        heat = create_heat_client(host_ip)
        try:
            LOG.debug('%s: 发送删除请求', req_id)
            heat.stacks.delete(app_ins_mapper.stack_id)
        except HTTPNotFound:
            LOG.debug('%s: stack不存在', req_id)
            pass
        except Exception as e:
            LOG.error(e, exc_info=True)
            return res

        app_ins_mapper.operational_status = utils.TERMINATING
        LOG.debug('%s: 更新数据库状态', req_id)
        commit()

        LOG.debug('%s: 开始状态更新定时任务', req_id)
        start_check_stack_status(app_instance_id=app_instance_id)

        res.status = utils.SUCCESS
        LOG.debug('%s: 处理请求完成', req_id)
        return res

    @db_session
    def query(self, request, context):
        """
        实例信息查询
        :param request:
        :param context:
        :return:
        """
        LOG.debug('receive query msg...')
        res = QueryResponse(response='{"code": 500, "msg": "server error"}')

        host_ip = validate_input_params(request)
        if host_ip is None:
            return res

        app_instance_id = request.appInstanceId
        if app_instance_id is None:
            return res

        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if app_ins_mapper is None:
            return res

        heat = create_heat_client(host_ip)
        output_list = heat.stacks.output_list(app_ins_mapper.stack_id)

        response = {
            'code': 200,
            'msg': 'ok',
            'data': []
        }
        for item in output_list['outputs']:
            output = heat.stacks.output_show(app_ins_mapper.stack_id, item['output_key'])
            output_value = output['output']['output_value']
            item = {
                'vmId': output_value['vmId'],
                'vncUrl': output_value['vncUrl'],
                'networks': []
            }
            for net_name, ip_data in output_value['networks'].items():
                if utils.validate_uuid(net_name):
                    continue
                network = {
                    'name': net_name,
                    'ip': ip_data[0]['addr']
                }
                item['networks'].append(network)
            response['data'].append(item)

        res.response = json.dumps(response)
        return res

    @db_session
    def workloadEvents(self, request, context):
        """
        工作负载事件查询
        :param request:
        :param context:
        :return:
        """
        LOG.debug('receive workload describe msg...')
        res = WorkloadEventsResponse(response='{"code":500}')

        host_ip = validate_input_params(request)
        if host_ip is None:
            return res

        app_instance_id = request.appInstanceId
        if app_instance_id is None:
            return res

        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if app_ins_mapper is None:
            LOG.info('app实例 %s 不存在', app_instance_id)
            return res

        heat = create_heat_client(host_ip)

        events = heat.events.list(stack_id=app_ins_mapper.stack_id)
        vm_describe_info = {}
        for event in events:
            if event.resource_name in vm_describe_info:
                vm_describe_info[event.resource_name]['events'].append({
                    'eventTime': event.event_time,
                    'resourceStatus': event.resource_status,
                    'resourceStatusReason': event.resource_status_reason
                })
            else:
                vm_describe_info[event.resource_name] = {
                    'resourceName': event.resource_name,
                    'logicalResourceId': event.logical_resource_id,
                    'physicalResourceId': event.physical_resource_id,
                    'events': [
                        {
                            'eventTime': event.event_time,
                            'resourceStatus': event.resource_status,
                            'resourceStatusReason': event.resource_status_reason
                        }
                    ]
                }
        response_data = []
        for key, value in vm_describe_info.items():
            response_data.append(value)
        res.response = json.dumps(response_data)
        return res

    def uploadConfig(self, request_iterator, context):
        """
        上传openstack配置文件
        :param request_iterator: 流式传输
        :param context:
        :return:
        """
        LOG.debug('receive uploadConfig msg...')
        res = UploadCfgResponse(status=utils.FAILURE)

        parameter = UploadCfgRequest(request_iterator)

        host_ip = validate_input_params(parameter)
        if host_ip is None:
            return res

        config_file = parameter.config_file
        if config_file is None:
            return res

        config_path = utils.RC_FILE_DIR + '/' + host_ip

        try:
            with open(config_path, 'wb') as new_file:
                new_file.write(config_file)
                res.status = utils.SUCCESS
        except Exception as e:
            LOG.error(e, exc_info=True)

        return res

    def removeConfig(self, request, context):
        """
        删除openstack 配置文件
        :param request: 请求体
        :param context: 上下文信息
        :return: Success/Failure
        """
        LOG.debug('receive removeConfig msg...')
        res = RemoveCfgResponse(status=utils.FAILURE)

        host_ip = validate_input_params(request)
        if not host_ip:
            return res

        config_path = utils.RC_FILE_DIR + '/' + host_ip
        try:
            os.remove(config_path)
            res.status = utils.SUCCESS
        except OSError as e:
            LOG.debug(e)
            res.status = utils.SUCCESS
        except Exception as e:
            LOG.error(e, exc_info=True)
            return res

        LOG.info('host configuration file deleted successfully')
        return res
