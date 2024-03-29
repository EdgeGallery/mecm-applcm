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
import uuid

from novaclient.exceptions import Forbidden

from core import openstack_utils
from core.csar.pkg import CsarPkg
from core.log import logger
from core.models import AppInsMapper, UploadCfgRequest, \
    UploadPackageRequest, AppPkgMapper, VmImageInfoMapper
from core.openstack_utils import create_glance_client, create_heat_client, \
    create_nova_client, create_neutron_client, create_cinder_client

import glanceclient.exc

from heatclient.common import template_utils
from heatclient.exc import HTTPNotFound
from internal.lcmservice import lcmservice_pb2_grpc
from internal.lcmservice.lcmservice_pb2 import TerminateResponse, \
    QueryResponse, UploadCfgResponse, \
    RemoveCfgResponse, DeletePackageResponse, UploadPackageResponse, \
    WorkloadEventsResponse, InstantiateResponse, QueryKPIResponse, QueryPackageStatusResponse

from pony.orm import db_session, rollback, commit
from task.app_instance_task import start_check_stack_status
from task.app_package_task import start_check_package_status

import utils

LOG = logger


def _get_output_data(output_list, heat, stack_id):
    """
    获取output数据
    """
    response = {
        'code': 200,
        'msg': 'ok',
        'status': utils.INSTANTIATED,
        'data': []
    }
    for item in output_list['outputs']:
        output = heat.stacks.output_show(stack_id, item['output_key'])
        output_value = output['output']['output_value']
        item = {
            'vmId': output_value['vmId'],
            'networks': []
        }
        if 'networks' in output_value and output_value['networks'] is not None:
            for net_name, ip_data in output_value['networks'].items():
                if utils.validate_uuid(net_name):
                    continue
                network = {
                    'name': net_name,
                    'ip': ip_data[0]['addr']
                }
                item['networks'].append(network)
            response['data'].append(item)
    return response


class AppLcmService(lcmservice_pb2_grpc.AppLCMServicer):
    """
    AppLcmService
    """

    @db_session
    def uploadPackage(self, request_iterator, context):
        """
        上传app包
        :param request_iterator:
        :param context:
        :return:
        """
        LOG.info('receive upload package msg...')
        resp = UploadPackageResponse(status=utils.FAILURE)

        request = UploadPackageRequest(request_iterator)

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            request.delete_tmp()
            return resp

        app_package_id = request.appPackageId
        if app_package_id is None:
            LOG.error('appPackageId is required')
            request.delete_tmp()
            return resp

        app_pkg_mapper = AppPkgMapper.get(app_package_id=app_package_id, host_ip=host_ip)
        if app_pkg_mapper is not None:
            LOG.error('app package exist')
            request.delete_tmp()
            return resp

        app_package_path = utils.APP_PACKAGE_DIR + '/' + host_ip + '/' + app_package_id
        AppPkgMapper(
            app_package_id=app_package_id,
            host_ip=host_ip,
            status=utils.UPLOADING,
            app_package_path=app_package_path
        )
        try:
            LOG.debug('unzip package')
            request.unzip(app_package_path)
            pkg = CsarPkg(app_package_id, app_package_path)
            pkg.check_image(host_ip, request.tenantId)
            pkg.translate()
            commit()
            start_check_package_status(app_package_id, host_ip)
            resp.status = utils.SUCCESS
            LOG.info('upload and analyze app package success, start fetch image')
        except Exception as exception:
            rollback()
            LOG.error(exception, exc_info=True)
            utils.delete_dir(app_package_path)
        finally:
            request.delete_tmp()
        return resp

    @db_session
    def deletePackage(self, request, context):
        """
        删除app包
        :param request:
        :param context:
        :return:
        """
        LOG.info('receive delete package msg...')
        res = DeletePackageResponse(status=utils.FAILURE)

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return res

        app_package_id = request.appPackageId
        if app_package_id is None or app_package_id == '':
            LOG.error("appPackageId required")
            return res

        app_package_mapper = AppPkgMapper.get(app_package_id=app_package_id,
                                              host_ip=host_ip)

        if app_package_mapper is not None:
            utils.delete_dir(app_package_mapper.app_package_path)
            app_package_mapper.delete()

        glance = create_glance_client(host_ip, request.tenantId)
        images = VmImageInfoMapper.find_many(app_package_id=app_package_id,
                                             host_ip=host_ip)
        for image in images:
            try:
                glance.images.delete(image.image_id)
            except glanceclient.exc.HTTPNotFound:
                logger.debug('skip delete image %s', image.image_id)
            image.delete()
        commit()

        res.status = utils.SUCCESS
        LOG.info('delete app package success')
        return res

    @db_session
    def instantiate(self, request, context):
        """
        app 实例化
        :param request:
        :param context:
        :return:
        """
        LOG.info('receive instantiate msg...')
        resp = InstantiateResponse(status=utils.FAILURE)

        LOG.debug('校验access token, host ip')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return resp

        LOG.debug('获取实例ID')
        if not request.appInstanceId:
            LOG.error(utils.APP_INS_ERR_MDG)
            return resp

        LOG.debug('查询数据库是否存在相同记录')
        if AppInsMapper.get(app_instance_id=request.appInstanceId) is not None:
            LOG.error('app ins %s exist', request.appInstanceId)
            return resp

        LOG.debug('检查app包状态')
        app_pkg_mapper = AppPkgMapper.get(app_package_id=request.appPackageId,
                                          host_ip=host_ip)
        if app_pkg_mapper is None or app_pkg_mapper.status != utils.UPLOADED:
            LOG.error('app pkg %s not uploaded', request.appPackageId)
            return resp

        csar = CsarPkg(app_pkg_mapper.app_package_id, app_pkg_mapper.app_package_path)

        LOG.debug('构建heat参数')
        tpl_files, template = template_utils.get_template_contents(template_file=csar.hot_path)

        parameters = {}
        for key in template['parameters'].keys():
            if key in request.parameters:
                parameters[key] = request.parameters[key]

        if not request.akSkLcmGen and 'ak' in parameters and 'sk' in parameters:
            parameters['ak'] = ''
            parameters['sk'] = ''

        csar.create_request_networks(request.hostIp, request.tenantId, parameters)

        fields = {
            'stack_name': 'eg-' + ''.join(str(uuid.uuid4()).split('-'))[0:8],
            'template': template,
            'files': dict(list(tpl_files.items())),
            'parameters': parameters
        }

        heat = create_heat_client(host_ip, request.tenantId)
        try:
            LOG.debug('发送创建stack请求')
            stack_resp = heat.stacks.create(**fields)
        except Exception as exception:
            LOG.error(exception, exc_info=True)
            return resp
        AppInsMapper(app_instance_id=request.appInstanceId,
                     host_ip=host_ip,
                     tenant_id=request.tenantId,
                     stack_id=stack_resp['stack']['id'],
                     operational_status=utils.INSTANTIATING)
        commit()
        LOG.debug('更新数据库')

        LOG.debug('开始更新状态定时任务')
        start_check_stack_status(app_instance_id=request.appInstanceId)

        resp.status = utils.SUCCESS
        LOG.info('instantiate success')
        return resp

    @db_session
    def terminate(self, request, context):
        """
        销毁实例
        :param request:
        :param context:
        :return:
        """
        LOG.info('receive terminate msg...')
        res = TerminateResponse(status=utils.FAILURE)

        LOG.debug('校验token, host ip')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return res

        LOG.debug('获取实例ID')
        app_instance_id = request.appInstanceId
        if app_instance_id is None or app_instance_id == '':
            LOG.error(utils.APP_INS_ERR_MDG)
            return res

        LOG.debug('查询数据库')
        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if app_ins_mapper is None:
            res.status = utils.SUCCESS
            return res

        LOG.debug('初始化openstack客户端')
        heat = create_heat_client(host_ip, app_ins_mapper.tenant_id)
        try:
            LOG.debug('发送删除请求')
            heat.stacks.delete(app_ins_mapper.stack_id)
        except HTTPNotFound:
            LOG.debug('stack不存在')
        except Exception as exception:
            LOG.error(exception, exc_info=True)
            return res

        app_ins_mapper.operational_status = utils.TERMINATING
        commit()
        LOG.debug('更新数据库状态')

        LOG.debug('开始状态更新定时任务')
        start_check_stack_status(app_instance_id=app_instance_id)

        res.status = utils.SUCCESS
        LOG.info('success terminate app')
        return res

    @db_session
    def query(self, request, context):
        """
        实例信息查询
        :param request:
        :param context:
        :return:
        """
        LOG.info('receive query msg...')
        res = QueryResponse(response='{"code": 500, "msg": "server error"}')

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            res.response = '{"code":400}'
            return res

        app_instance_id = request.appInstanceId
        if app_instance_id is None or app_instance_id == '':
            LOG.error(utils.APP_INS_ERR_MDG)
            res.response = '{"code":400}'
            return res

        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if app_ins_mapper is None:
            res.response = '{"code":404}'
            return res

        if app_ins_mapper.operational_status != utils.INSTANTIATED:
            res_data = {
                'code': 200,
                'msg': app_ins_mapper.operation_info,
                'status': app_ins_mapper.operational_status
            }
            res.response = json.dumps(res_data)
            LOG.info('query app instance info success')
            return res

        heat = create_heat_client(host_ip, app_ins_mapper.tenant_id)
        output_list = heat.stacks.output_list(app_ins_mapper.stack_id)

        response = _get_output_data(output_list, heat, app_ins_mapper.stack_id)

        res.response = json.dumps(response)
        return res

    @db_session
    def queryPackageStatus(self, request, context):
        """
        查询app包加载状态
        Args:
            request:
            context:

        Returns:

        """
        LOG.info('receive query app package msg...')
        resp = QueryPackageStatusResponse(response=utils.ERROR)

        LOG.debug('校验access token, host ip')
        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return resp

        LOG.debug('检查app包状态')
        app_pkg_mapper = AppPkgMapper.get(app_package_id=request.packageId,
                                          host_ip=host_ip)

        if app_pkg_mapper is None:
            LOG.error('app package %s not found', request.packageId)
            resp.response = '404'
            return resp

        resp.response = app_pkg_mapper.status

        return resp

    @db_session
    def queryKPI(self, request, context):
        """
        查询host资源信息
        Args:
            request:
            context:

        Returns:

        """
        LOG.info('received query kpi message')
        resp = QueryKPIResponse(response=utils.FAILURE_JSON)

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return resp

        nova = create_nova_client(host_ip, request.tenantId)
        cinder = create_cinder_client(host_ip, request.tenantId)
        neutron = create_neutron_client(host_ip, request.tenantId)
        os_project_id = nova.client.session.get_project_id()

        resp_data = {
            'retCode': 200,
            'message': 'success'
        }

        quotas = nova.limits.get().absolute

        net_usage = neutron.show_quota_details(os_project_id)
        volume_usage = cinder.limits.get(tenant_id=os_project_id).absolute

        quota_dict = {}
        try:
            hypervisors = nova.hypervisors.list()
            local_gb = 0
            local_gb_used = 0
            for hypervisor in hypervisors:
                local_gb = local_gb + hypervisor.local_gb
                local_gb_used = local_gb_used + hypervisor.local_gb_used
            quota_dict['local_gb'] = local_gb
            quota_dict['local_gb_used'] = local_gb_used
            quota_dict['virtual_local_storage_used'] = local_gb_used
            quota_dict['virtual_local_storage_total'] = local_gb
        except Forbidden:
            logger.warn('not permitted to get hypervisors info')

        for quota in quotas:
            quota_dict[quota.name] = quota.value

        for usage in volume_usage:
            quota_dict[usage.name] = usage.value

        for (key, value) in net_usage['quota'].items():
            quota_dict[key + 'Limit'] = value['limit']
            quota_dict[key + 'Used'] = value['used']

        quota_dict['virtual_mem_used'] = quota_dict['totalRAMUsed']
        quota_dict['virtual_mem_total'] = quota_dict['maxTotalRAMSize']
        quota_dict['virtual_cpu_used'] = quota_dict['totalCoresUsed']
        quota_dict['virtual_cpu_total'] = quota_dict['maxTotalCores']

        resp_data['data'] = quota_dict
        resp.response = json.dumps(resp_data)

        LOG.info('success query kpi')

        return resp

    @db_session
    def workloadEvents(self, request, context):
        """
        工作负载事件查询
        :param request:
        :param context:
        :return:
        """
        LOG.info('receive workload describe msg...')
        res = WorkloadEventsResponse(response='{"code":500}')

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return res

        app_instance_id = request.appInstanceId
        if app_instance_id is None or app_instance_id == '':
            LOG.error(utils.APP_INS_ERR_MDG)
            return res

        app_ins_mapper = AppInsMapper.get(app_instance_id=app_instance_id)
        if app_ins_mapper is None:
            LOG.debug('app实例 %s 不存在', app_instance_id)
            res.response = '{"code":404}'
            return res

        heat = create_heat_client(host_ip, app_ins_mapper.tenant_id)

        events = heat.events.list(stack_id=app_ins_mapper.stack_id)
        vm_describe_info = {}
        for event in events:
            if event['resource_name'] in vm_describe_info:
                vm_describe_info[event['resource_name']]['events'].append({
                    'eventTime': event['event_time'],
                    'resourceStatus': event['resource_status'],
                    'resourceStatusReason': event['resource_status_reason']
                })
            else:
                vm_describe_info[event['resource_name']] = {
                    'resourceName': event['resource_name'],
                    'logicalResourceId': event['logical_resource_id'],
                    'physicalResourceId': event['physical_resource_id'],
                    'events': [
                        {
                            'eventTime': event['event_time'],
                            'resourceStatus': event['resource_status'],
                            'resourceStatusReason': event['resource_status_reason']
                        }
                    ]
                }
        response_data = []
        for value in vm_describe_info.values():
            response_data.append(value)
        res.response = json.dumps(response_data)
        LOG.info('query workload events success')
        return res

    def uploadConfig(self, request_iterator, context):
        """
        上传openstack配置文件
        :param request_iterator: 流式传输
        :param context:
        :return:
        """
        LOG.info('receive uploadConfig msg...')
        res = UploadCfgResponse(status=utils.FAILURE)

        request = UploadCfgRequest(request_iterator)

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return res

        config_file = request.configFile
        if config_file is None:
            LOG.info('configFile is required')
            return res

        config_path_dir = utils.RC_FILE_DIR + '/' + request.tenantId
        if not utils.exists_path(config_path_dir):
            utils.create_dir(config_path_dir)
        config_path = config_path_dir + '/' + host_ip

        try:
            with open(config_path, 'wb') as new_file:
                new_file.write(config_file)
            openstack_utils.set_rc(host_ip, request.tenantId)
            res.status = utils.SUCCESS
        except Exception as exception:
            LOG.error(exception, exc_info=True)
            return res

        LOG.info('upload host configuration success')
        return res

    def removeConfig(self, request, context):
        """
        删除openstack 配置文件
        :param request: 请求体
        :param context: 上下文信息
        :return: Success/Failure
        """
        LOG.info('receive removeConfig msg...')
        res = RemoveCfgResponse(status=utils.FAILURE)

        host_ip = utils.validate_input_params(request)
        if host_ip is None:
            return res

        config_path = utils.RC_FILE_DIR + '/' + request.tenantId + '/' + host_ip
        try:
            if os.path.exists(config_path):
                os.remove(config_path)
            openstack_utils.del_rc(host_ip, request.tenantId)
            res.status = utils.SUCCESS
        except Exception as exception:
            LOG.error(exception, exc_info=True)
            return res

        LOG.info('host configuration file deleted successfully')
        return res
