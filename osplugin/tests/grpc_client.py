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


def make_terminate_request(access_token, app_instance_id, host_ip):
    return lcmservice_pb2.TerminateRequest(accessToken=access_token, appInstanceId=app_instance_id, hostIp=host_ip)


def make_create_image_request(access_token, host_ip, app_instance_id, vm_id):
    return lcmservice_pb2.CreateVmImageRequest(accessToken=access_token, hostIp=host_ip, appInstanceId=app_instance_id,
                                               vmId=vm_id)


def make_delete_image_request(access_token, host_ip, app_instance_id, image_id):
    return lcmservice_pb2.DeleteVmImageRequest(accessToken=access_token, hostIp=host_ip, appInstanceId=app_instance_id,
                                               imageId=image_id)


def make_download_image_request(access_token, chunk_num, host_ip, app_instance_id, image_id):
    return lcmservice_pb2.DownloadVmImageRequest(accessToken=access_token, hostIp=host_ip, chunkNum=chunk_num,
                                                 appInstanceId=app_instance_id,
                                                 imageId=image_id)


if __name__ == '__main__':
    with grpc.insecure_channel('localhost:8234') as channel:
        # stub = lcmservice_pb2_grpc.VmImageStub(channel)
        # response1 = stub.createVmImage(
        #     make_create_image_request(access_token="test_access_token", host_ip=test_host_ip, app_instance_id="1",
        #                               vm_id="1"))

        # response = stub.deleteVmImage(
        #     make_delete_image_request(access_token="test_access_token", host_ip=test_host_ip, app_instance_id="1",
        #                               image_id="98920865-8c34-4f32-a166-f7c06775a34a"))

        # response = stub.queryVmImage(
        #     make_delete_image_request(access_token="test_access_token", host_ip=test_host_ip, app_instance_id="1",
        #                               image_id="f514d88e-9c1f-4302-bbbc-6d045dc2a704"))

        # response = stub.downloadVmImage(
        #     make_download_image_request(access_token="test_access_token", host_ip=test_host_ip, chunk_num=1,
        #                                app_instance_id="1", image_id="cc038a08-fb1e-44a5-90cf-71ada395bb4b"))
        # print(str(response))
        stub2 = lcmservice_pb2_grpc.AppLCMStub(channel)

        response = stub2.instantiate(make_instantiate_request(access_token="test_access_token",
                                                              app_instance_id="3",
                                                              host_ip='10.10.9.75',
                                                              package_path="./resources/ht-package.zip",
                                                              ak="a",
                                                              sk="s"))
        """
        response = stub2.terminate(make_terminate_request(access_token=test_access_token,
                                                          app_instance_id="4",
                                                          host_ip='10.10.9.75'))"""
        print(str(response))
        # for i in range(1, 12975):
        #     response = stub.downloadVmImage(
        #         make_download_image_request(access_token="test_access_token", host_ip=test_host_ip, chunk_num=i,
        #                                     app_instance_id="1", image_id="f514d88e-9c1f-4302-bbbc-6d045dc2a704"))
        #     file = open('image.QCOW2', 'ab')
        #     print(response)
        #     for res in response:
        #         print(res)
        #         file.write(res.content)
# stub = lcmservice_pb2_grpc.AppLCMStub(channel)
# stub.terminate(lcmservice_pb2.TerminateRequest(accessToken=test_access_token,
#                                                hostIp=test_host_ip,
#                                                appInstanceId=''))
