import unittest

import grpc

import utils
from internal.lcmservice import lcmservice_pb2_grpc, lcmservice_pb2
from tests import gen_token


class GrpcServerTest(unittest.TestCase):
    access_token = gen_token.test_access_token
    host_ip = '159.138.23.91'

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        with open('target/ssl/server_tls.crt', 'rb') as f:
            root_certificates = f.read()
        credentials = grpc.ssl_channel_credentials(root_certificates=root_certificates)
        options = (
            ('grpc.ssl_target_name_override', 'edgegallery.org',),
        )
        channel = grpc.secure_channel(target='mecm-mepm-osplugin:8234', credentials=credentials, options=options)
        self.app_lcm_stub = lcmservice_pb2_grpc.AppLCMStub(channel)
        self.vm_image_stub = lcmservice_pb2_grpc.VmImageStub(channel)

    def test_create_image(self):
        request = lcmservice_pb2.CreateVmImageRequest(
            accessToken=self.access_token,
            appInstanceId='ins001',
            hostIp=self.host_ip,
            vmId='caf83c05-56dc-4f7c-b417-40d9acbf166c'
        )
        response = self.vm_image_stub.createVmImage(request)
        self.assertEqual(response.response, utils.SUCCESS)

    def test_upload_package(self):
        with open('tests/resources/ht-package.zip', 'rb') as f:
            package = f.read()
        request = iter([
            lcmservice_pb2.UploadPackageRequest(accessToken=self.access_token),
            lcmservice_pb2.UploadPackageRequest(hostIp=self.host_ip),
            lcmservice_pb2.UploadPackageRequest(appPackageId='pkg001'),
            lcmservice_pb2.UploadPackageRequest(tenantId='tenant001'),
            lcmservice_pb2.UploadPackageRequest(package=package)
        ])
        response = self.app_lcm_stub.uploadPackage(request)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_delete_package(self):
        request = lcmservice_pb2.DeletePackageRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appPackageId='pkg001',
            tenantId='tenant001',
        )
        response = self.app_lcm_stub.deletePackage(request)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_instantiate(self):
        request = lcmservice_pb2.InstantiateRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appInstanceId='ins001',
            appPackageId='pkg001',
            tenantId='tenant001',
            ak='ak001',
            sk='sk001'
        )
        response = self.app_lcm_stub.instantiate(request)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_terminate(self):
        request = lcmservice_pb2.TerminateRequest(
            accessToken=self.access_token,
            appInstanceId='ins001',
            hostIp=self.host_ip,
        )
        response = self.app_lcm_stub.terminate(request)
        self.assertEqual(response.status, utils.SUCCESS)

    def test_query(self):
        request = lcmservice_pb2.QueryRequest(
            accessToken=self.access_token,
            hostIp=self.host_ip,
            appInstanceId='ins001',
        )
        response = self.app_lcm_stub.query(request)
        print(response.response)