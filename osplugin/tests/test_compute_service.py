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

# !python3
# -*- coding: utf-8 -*-
import json
import os
import unittest
from unittest import mock

from pony.orm import db_session, commit

from core.models import VmImageInfoMapper
from internal.resourcemanager.resourcemanager_pb2 import CreateVmImageRequest, \
    DeleteVmImageRequest, QueryVmImageRequest, DownloadVmImageRequest, UploadVmImageRequest, ImportVmImageRequest, \
    CreateVmRequest, DeleteVmRequest, QueryVmRequest, CreateFlavorRequest, DeleteFlavorRequest, QueryFlavorRequest, \
    OperateVmRequest
from service.flavor_service import FlavorService
from service.image_service import ImageService
from service.vm_service import VmService
from tests.resources import gen_token
from tests.resources.test_data import mock_glance_client, mock_nova_client


def make_create_image_request(access_token, host_ip, tenant_id):
    """
    make_create_image_request
    """
    return CreateVmImageRequest(accessToken=access_token,
                                hostIp=host_ip,
                                tenantId=tenant_id,
                                image=CreateVmImageRequest.Image(
                                    name='test001',
                                    minRam=1024,
                                    minDisk=20,
                                    diskFormat='qcow2',
                                    containerFormat='bare',
                                    properties={
                                        'x86': 'true'
                                    }
                                ))


def make_upload_image_request(access_token, host_ip, tenant_id):
    """

    Args:
        access_token:
        host_ip:
        tenant_id:

    Returns:

    """
    yield UploadVmImageRequest(accessToken=access_token)
    yield UploadVmImageRequest(hostIp=host_ip)
    yield UploadVmImageRequest(tenantId=tenant_id)
    yield UploadVmImageRequest(imageId='abcabcabc')
    yield UploadVmImageRequest(content=b'abcabcabc')
    yield UploadVmImageRequest(content=b'abcabcabc')


def make_import_image_request(access_token, host_ip, tenant_id):
    """

    Args:
        access_token:
        host_ip:
        tenant_id:

    Returns:

    """
    return ImportVmImageRequest(accessToken=access_token,
                                hostIp=host_ip,
                                tenantId=tenant_id,
                                imageId='abcabcabc',
                                resourceUri='http://abcabc.com/abcab/abc.qcow2')


def make_delete_image_request(access_token, host_ip, tenant_id, image_id):
    """
    make_delete_image_request
    """
    return DeleteVmImageRequest(accessToken=access_token,
                                hostIp=host_ip,
                                tenantId=tenant_id,
                                imageId=image_id)


def make_query_image_request(access_token, host_ip, tenant_id, image_id):
    """
    make_delete_image_request
    """
    return QueryVmImageRequest(accessToken=access_token,
                               hostIp=host_ip,
                               tenantId=tenant_id,
                               imageId=image_id)


def make_download_image_request(access_token, host_ip, tenant_id):
    """
    make_download_image_request
    """
    return DownloadVmImageRequest(accessToken=access_token,
                                  hostIp=host_ip,
                                  tenantId=tenant_id,
                                  imageId='abcabcabcabc')


class ComputeServiceTest(unittest.TestCase):
    """
    测试 compute service
    """
    vm_image_service = ImageService()
    flavor_service = FlavorService()
    vm_service = VmService()
    access_token = gen_token.test_access_token
    host_ip = '10.10.9.75'
    tenant_id = 'tenant001'

    @mock.patch("service.image_service.create_glance_client")
    def test_create_image(self, create_glance_client):
        """
        test_create_image
        """
        create_glance_client.return_value = mock_glance_client
        request = make_create_image_request(access_token=self.access_token,
                                            host_ip=self.host_ip,
                                            tenant_id=self.tenant_id)
        resp = self.vm_image_service.createVmImage(request, None)
        resp_data = json.loads(resp.response)
        assert 'imageId' in resp_data['data']

    @mock.patch('service.image_service.create_glance_client')
    def test_delete_image(self, create_glance_client):
        """
        test_delete_image
        """
        request = make_delete_image_request(access_token=self.access_token,
                                            host_ip=self.host_ip,
                                            tenant_id=self.tenant_id,
                                            image_id="2fd65cfb-fa1e-4461-bc40-326a55f01803")
        create_glance_client.return_value = mock_glance_client
        with db_session:
            VmImageInfoMapper(
                image_id='2fd65cfb-fa1e-4461-bc40-326a55f01803',
                host_ip=self.host_ip,
                image_name='image01',
                disk_format='qcow2',
                status='active',
                image_size=1024,
                checksum='2',
                tenant_id='abcabc'
            )
            commit()
        resp = self.vm_image_service.deleteVmImage(request, None)
        assert resp.status == '{\"data\": null, \"retCode\": 200, \"message\": \"Delete Image Success\"}'

    @mock.patch('service.image_service.create_glance_client')
    def test_query_image(self, create_glance_client):
        """
        test_query_image
        """
        with db_session:
            VmImageInfoMapper(
                image_id='e8360231-14fe-4baf-b34a-5be17c62e2f8',
                host_ip=self.host_ip,
                image_name='image01',
                disk_format='qcow2',
                status='active',
                image_size=1024,
                checksum='2',
                tenant_id='abcabc',
                compress_task_id='abcabcabc'
            )
            commit()

        create_glance_client.return_value = mock_glance_client

        request = make_query_image_request(access_token=self.access_token,
                                           host_ip=self.host_ip,
                                           tenant_id=self.tenant_id,
                                           image_id="e8360231-14fe-4baf-b34a-5be17c62e2f8")
        resp = self.vm_image_service.queryVmImage(request, None)
        resp_data = json.loads(resp.response)
        assert 'imageId' in resp_data['data']

        query_request = QueryVmImageRequest(accessToken=self.access_token,
                                            hostIp=self.host_ip,
                                            tenantId=self.tenant_id)
        resp = self.vm_image_service.queryVmImage(query_request, None)
        resp_data = json.loads(resp.response)
        assert len(resp_data['data']) > 0

    @mock.patch('service.image_service.start_check_image_status')
    @mock.patch('service.image_service.create_glance_client')
    def test_download_image(self, create_glance_client, start_check_image_status):
        """
        test_download_image
        """
        create_glance_client.return_value = mock_glance_client
        start_check_image_status.return_value = None
        request = make_download_image_request(access_token=self.access_token,
                                              host_ip=self.host_ip,
                                              tenant_id=self.tenant_id)

        response = self.vm_image_service.downloadVmImage(request, None)
        with open('image.qcow2', 'ab') as file:
            for res in response:
                file.write(res.content)

        os.remove('image.qcow2')

    @mock.patch('service.image_service.start_check_image_status')
    @mock.patch('service.image_service.create_glance_client')
    def test_upload_image(self, create_glance_client, start_check_image_status):
        """

        Args:
            create_glance_client:

        Returns:

        """
        create_glance_client.return_value = mock_glance_client
        start_check_image_status.return_value = None
        request = make_upload_image_request(access_token=self.access_token,
                                            host_ip=self.host_ip,
                                            tenant_id=self.tenant_id)

        resp = self.vm_image_service.uploadVmImage(request, None)
        assert resp.status == '{\"data\": null, \"retCode\": 0, \"message\": \"Success\"}'

    @mock.patch('service.image_service.add_import_image_task')
    @mock.patch('service.image_service.create_glance_client')
    def test_import_image(self, create_glance_client, add_import_image_task):
        """

        Args:
            create_glance_client:

        Returns:

        """
        create_glance_client.return_value = mock_glance_client
        add_import_image_task.return_value = None
        request = make_import_image_request(access_token=self.access_token,
                                            host_ip=self.host_ip,
                                            tenant_id=self.tenant_id)
        resp = self.vm_image_service.importVmImage(request, None)
        assert resp.status == '{\"data\": null, \"retCode\": 200, \"message\": \"success\"}'

    @mock.patch('service.vm_service.create_nova_client')
    def test_create_vm(self, create_nova_client):
        create_nova_client.return_value = mock_nova_client
        request = CreateVmRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            server=CreateVmRequest.Server(
                name='testVm',
                flavor='22e1a2f4-9f75-4baa-a6e4-f613deebc4ca',
                image='783b1d93-3c23-4e4c-a0ed-98ca27137628',
                networks=[
                    CreateVmRequest.Server.Network(
                        network='32b0f4fd-66ba-44b4-8a7e-ccdb0d7dc61e'
                    )
                ]
            )
        )
        resp = self.vm_service.createVm(request, None)
        assert resp.status == '{\"data\": null, \"retCode\": 0, \"message\": \"Create Success\"}'

    @mock.patch('service.vm_service.create_nova_client')
    def test_delete_vm(self, create_nova_client):
        create_nova_client.return_value = mock_nova_client
        request = DeleteVmRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            vmId='vm001'
        )
        resp = self.vm_service.deleteVm(request, None)
        assert resp.status == '{\"data\": null, \"retCode\":200, \"message\":\"success\"}'

    @mock.patch('service.vm_service.create_nova_client')
    def test_query_vm(self, create_nova_client):
        create_nova_client.return_value = mock_nova_client
        request = QueryVmRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
        )
        resp = self.vm_service.queryVm(request, None)
        resp_data = json.loads(resp.response)
        assert len(resp_data['data']) > 0
        request = QueryVmRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            vmId='aabbccvm01'
        )
        resp = self.vm_service.queryVm(request, None)
        resp_data = json.loads(resp.response)
        assert resp_data['data']['id'] == 'aabbccvm01'

    @mock.patch('service.vm_service.start_check_image_status')
    @mock.patch('service.vm_service.create_nova_client')
    def test_operate_vm(self, create_nova_client, start_check_image_status):
        create_nova_client.return_value = mock_nova_client
        start_check_image_status.return_value = None
        request = OperateVmRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            vmId='61fcdb06-9375-4711-9fbd-2989a4e0f9a6',
            action='createImage',
            createImage=OperateVmRequest.CreateImage(
                name='test_image'
            )
        )
        resp = self.vm_service.operateVm(request, None)
        print(resp)
        assert resp.response == '{\"data\": \"aabbccvmimage01\", \"retCode\": 200, \"message\": \"Success\"}'

    @mock.patch('service.flavor_service.create_nova_client')
    def test_create_flavor(self, create_nova_client):
        create_nova_client.return_value = mock_nova_client
        request = CreateFlavorRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            flavor=CreateFlavorRequest.Flavor(
                name='test-create-flavor',
                vcpus=1,
                ram=1024,
                disk=20,
                extraSpecs={
                    'x86': 'true'
                }
            )
        )
        resp = self.flavor_service.createFlavor(request, None)
        assert resp.status == '{\"data\": null, \"retCode\": 0, \"message\": \"Success\"}'

    @mock.patch('service.flavor_service.create_nova_client')
    def test_delete_flavor(self, create_nova_client):
        create_nova_client.return_value = mock_nova_client
        request = DeleteFlavorRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            flavorId='b8921147-8fbb-4c60-93d8-b42504d23bca'
        )
        resp = self.flavor_service.deleteFlavor(request, None)
        print(resp)

    @mock.patch('service.flavor_service.create_nova_client')
    def test_query_flavor(self, create_nova_client):
        create_nova_client.return_value = mock_nova_client
        request = QueryFlavorRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
        )
        resp = self.flavor_service.queryFlavor(request, None)
        resp_data = json.loads(resp.response)
        assert len(resp_data['data'])
        request = QueryFlavorRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            tenantId=self.tenant_id,
            flavorId='abcabc'
        )
        resp = self.flavor_service.queryFlavor(request, None)
        resp_data = json.loads(resp.response)
        assert resp_data['data']['id'] == 'abcabc'
