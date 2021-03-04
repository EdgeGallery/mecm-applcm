#!python3
# -*- coding: utf-8 -*-
import grpc
from internal.lcmservice import lcmservice_pb2_grpc
from internal.lcmservice import lcmservice_pb2
from tests.test_data import test_access_token, test_host_ip


def make_upload_request(access_token, host_ip, config_file_data):
    requests = [
        lcmservice_pb2.UploadCfgRequest(accessToken=access_token),
        lcmservice_pb2.UploadCfgRequest(hostIp=host_ip),
        lcmservice_pb2.UploadCfgRequest(configFile=config_file_data)
    ]
    for request in requests:
        yield request


def make_instantiate_request(access_token, app_instance_id, host_ip, package_path, ak, sk):
    with open(package_path, 'rb') as package:
        package_data = package.read()
    requests = [
        lcmservice_pb2.InstantiateRequest(accessToken=access_token),
        lcmservice_pb2.InstantiateRequest(appInstanceId=app_instance_id),
        lcmservice_pb2.InstantiateRequest(hostIp=host_ip),
        lcmservice_pb2.InstantiateRequest(package=package_data),
        lcmservice_pb2.InstantiateRequest(ak=ak),
        lcmservice_pb2.InstantiateRequest(sk=sk)
    ]
    for request in requests:
        yield request


if __name__ == '__main__':
    with grpc.insecure_channel('localhost:8234') as channel:
        stub = lcmservice_pb2_grpc.AppLCMStub(channel)
        stub.terminate(lcmservice_pb2.TerminateRequest(accessToken=test_access_token,
                                                       hostIp=test_host_ip,
                                                       appInstanceId=''))
