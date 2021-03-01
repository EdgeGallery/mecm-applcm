# -*- coding: utf-8 -*-
from internal.lcmservice import lcmservice_pb2_grpc


class AppLcmService(lcmservice_pb2_grpc.AppLCMServicer):
    def instantiate(self, request_iterator, context):
        pass

    def terminate(self, request, context):
        pass

    def query(self, request, context):
        pass

    def uploadConfig(self, request_iterator, context):
        pass

    def removeConfig(self, request, context):
        pass

    def workloadDescribe(self, request, context):
        pass
