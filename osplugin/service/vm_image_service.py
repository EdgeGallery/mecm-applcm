# -*- coding: utf-8 -*-
from internal.lcmservice import lcmservice_pb2_grpc


class VmImageService(lcmservice_pb2_grpc.VmImageServicer):
    def createVmImage(self, request, context):
        pass

    def queryVmImage(self, request, context):
        pass

    def deleteVmImage(self, request, context):
        pass

    def downloadVmImage(self, request, context):
        pass
