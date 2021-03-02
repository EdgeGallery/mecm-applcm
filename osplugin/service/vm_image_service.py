# -*- coding: utf-8 -*-
from internal.lcmservice import lcmservice_pb2_grpc
from core.openstack_utils import create_nova_client
from core.openstack_utils import create_glance_client
from core.models import VmImageInfoMapper
from core.models import AppInsMapper


class VmImageService(lcmservice_pb2_grpc.VmImageServicer):

    def createVmImage(self, request, context):
        print(request)
        client = create_nova_client(request.hostIp)
        response = client.servers.create_server_image(request.vmId)
        print(response)

    def queryVmImage(self, request, context):
        pass

    def deleteVmImage(self, request, context):
        pass

    def downloadVmImage(self, request, context):
        pass
