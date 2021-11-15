# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import internal.lcmservice.lcmservice_pb2 as lcmservice__pb2


class AppLCMStub(object):
    """app lcm entity end

    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.instantiate = channel.unary_unary(
                '/internal.lcmservice.AppLCM/instantiate',
                request_serializer=lcmservice__pb2.InstantiateRequest.SerializeToString,
                response_deserializer=lcmservice__pb2.InstantiateResponse.FromString,
                )
        self.terminate = channel.unary_unary(
                '/internal.lcmservice.AppLCM/terminate',
                request_serializer=lcmservice__pb2.TerminateRequest.SerializeToString,
                response_deserializer=lcmservice__pb2.TerminateResponse.FromString,
                )
        self.query = channel.unary_unary(
                '/internal.lcmservice.AppLCM/query',
                request_serializer=lcmservice__pb2.QueryRequest.SerializeToString,
                response_deserializer=lcmservice__pb2.QueryResponse.FromString,
                )
        self.queryKPI = channel.unary_unary(
                '/internal.lcmservice.AppLCM/queryKPI',
                request_serializer=lcmservice__pb2.QueryKPIRequest.SerializeToString,
                response_deserializer=lcmservice__pb2.QueryKPIResponse.FromString,
                )
        self.queryPackageStatus = channel.unary_unary(
                '/internal.lcmservice.AppLCM/queryPackageStatus',
                request_serializer=lcmservice__pb2.QueryPackageStatusRequest.SerializeToString,
                response_deserializer=lcmservice__pb2.QueryPackageStatusResponse.FromString,
                )
        self.uploadConfig = channel.stream_unary(
                '/internal.lcmservice.AppLCM/uploadConfig',
                request_serializer=lcmservice__pb2.UploadCfgRequest.SerializeToString,
                response_deserializer=lcmservice__pb2.UploadCfgResponse.FromString,
                )
        self.removeConfig = channel.unary_unary(
                '/internal.lcmservice.AppLCM/removeConfig',
                request_serializer=lcmservice__pb2.RemoveCfgRequest.SerializeToString,
                response_deserializer=lcmservice__pb2.RemoveCfgResponse.FromString,
                )
        self.workloadEvents = channel.unary_unary(
                '/internal.lcmservice.AppLCM/workloadEvents',
                request_serializer=lcmservice__pb2.WorkloadEventsRequest.SerializeToString,
                response_deserializer=lcmservice__pb2.WorkloadEventsResponse.FromString,
                )
        self.uploadPackage = channel.stream_unary(
                '/internal.lcmservice.AppLCM/uploadPackage',
                request_serializer=lcmservice__pb2.UploadPackageRequest.SerializeToString,
                response_deserializer=lcmservice__pb2.UploadPackageResponse.FromString,
                )
        self.deletePackage = channel.unary_unary(
                '/internal.lcmservice.AppLCM/deletePackage',
                request_serializer=lcmservice__pb2.DeletePackageRequest.SerializeToString,
                response_deserializer=lcmservice__pb2.DeletePackageResponse.FromString,
                )


class AppLCMServicer(object):
    """app lcm entity end

    """

    def instantiate(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def terminate(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def query(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def queryKPI(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def queryPackageStatus(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def uploadConfig(self, request_iterator, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def removeConfig(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def workloadEvents(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def uploadPackage(self, request_iterator, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def deletePackage(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_AppLCMServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'instantiate': grpc.unary_unary_rpc_method_handler(
                    servicer.instantiate,
                    request_deserializer=lcmservice__pb2.InstantiateRequest.FromString,
                    response_serializer=lcmservice__pb2.InstantiateResponse.SerializeToString,
            ),
            'terminate': grpc.unary_unary_rpc_method_handler(
                    servicer.terminate,
                    request_deserializer=lcmservice__pb2.TerminateRequest.FromString,
                    response_serializer=lcmservice__pb2.TerminateResponse.SerializeToString,
            ),
            'query': grpc.unary_unary_rpc_method_handler(
                    servicer.query,
                    request_deserializer=lcmservice__pb2.QueryRequest.FromString,
                    response_serializer=lcmservice__pb2.QueryResponse.SerializeToString,
            ),
            'queryKPI': grpc.unary_unary_rpc_method_handler(
                    servicer.queryKPI,
                    request_deserializer=lcmservice__pb2.QueryKPIRequest.FromString,
                    response_serializer=lcmservice__pb2.QueryKPIResponse.SerializeToString,
            ),
            'queryPackageStatus': grpc.unary_unary_rpc_method_handler(
                    servicer.queryPackageStatus,
                    request_deserializer=lcmservice__pb2.QueryPackageStatusRequest.FromString,
                    response_serializer=lcmservice__pb2.QueryPackageStatusResponse.SerializeToString,
            ),
            'uploadConfig': grpc.stream_unary_rpc_method_handler(
                    servicer.uploadConfig,
                    request_deserializer=lcmservice__pb2.UploadCfgRequest.FromString,
                    response_serializer=lcmservice__pb2.UploadCfgResponse.SerializeToString,
            ),
            'removeConfig': grpc.unary_unary_rpc_method_handler(
                    servicer.removeConfig,
                    request_deserializer=lcmservice__pb2.RemoveCfgRequest.FromString,
                    response_serializer=lcmservice__pb2.RemoveCfgResponse.SerializeToString,
            ),
            'workloadEvents': grpc.unary_unary_rpc_method_handler(
                    servicer.workloadEvents,
                    request_deserializer=lcmservice__pb2.WorkloadEventsRequest.FromString,
                    response_serializer=lcmservice__pb2.WorkloadEventsResponse.SerializeToString,
            ),
            'uploadPackage': grpc.stream_unary_rpc_method_handler(
                    servicer.uploadPackage,
                    request_deserializer=lcmservice__pb2.UploadPackageRequest.FromString,
                    response_serializer=lcmservice__pb2.UploadPackageResponse.SerializeToString,
            ),
            'deletePackage': grpc.unary_unary_rpc_method_handler(
                    servicer.deletePackage,
                    request_deserializer=lcmservice__pb2.DeletePackageRequest.FromString,
                    response_serializer=lcmservice__pb2.DeletePackageResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'internal.lcmservice.AppLCM', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class AppLCM(object):
    """app lcm entity end

    """

    @staticmethod
    def instantiate(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/internal.lcmservice.AppLCM/instantiate',
            lcmservice__pb2.InstantiateRequest.SerializeToString,
            lcmservice__pb2.InstantiateResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def terminate(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/internal.lcmservice.AppLCM/terminate',
            lcmservice__pb2.TerminateRequest.SerializeToString,
            lcmservice__pb2.TerminateResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def query(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/internal.lcmservice.AppLCM/query',
            lcmservice__pb2.QueryRequest.SerializeToString,
            lcmservice__pb2.QueryResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def queryKPI(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/internal.lcmservice.AppLCM/queryKPI',
            lcmservice__pb2.QueryKPIRequest.SerializeToString,
            lcmservice__pb2.QueryKPIResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def queryPackageStatus(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/internal.lcmservice.AppLCM/queryPackageStatus',
            lcmservice__pb2.QueryPackageStatusRequest.SerializeToString,
            lcmservice__pb2.QueryPackageStatusResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def uploadConfig(request_iterator,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.stream_unary(request_iterator, target, '/internal.lcmservice.AppLCM/uploadConfig',
            lcmservice__pb2.UploadCfgRequest.SerializeToString,
            lcmservice__pb2.UploadCfgResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def removeConfig(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/internal.lcmservice.AppLCM/removeConfig',
            lcmservice__pb2.RemoveCfgRequest.SerializeToString,
            lcmservice__pb2.RemoveCfgResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def workloadEvents(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/internal.lcmservice.AppLCM/workloadEvents',
            lcmservice__pb2.WorkloadEventsRequest.SerializeToString,
            lcmservice__pb2.WorkloadEventsResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def uploadPackage(request_iterator,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.stream_unary(request_iterator, target, '/internal.lcmservice.AppLCM/uploadPackage',
            lcmservice__pb2.UploadPackageRequest.SerializeToString,
            lcmservice__pb2.UploadPackageResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def deletePackage(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/internal.lcmservice.AppLCM/deletePackage',
            lcmservice__pb2.DeletePackageRequest.SerializeToString,
            lcmservice__pb2.DeletePackageResponse.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
