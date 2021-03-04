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
    with grpc.insecure_channel('localhost:8888') as channel:
        stub = lcmservice_pb2_grpc.VmImageStub(channel)
        response = stub.createVmImage(
            make_create_image_request(access_token="test_access_token", host_ip=test_host_ip, app_instance_id="1",
                                      vm_id="fab3acb9-9927-468d-a784-b528fcf297cb"))

        # response = stub.deleteVmImage(
        #     make_delete_image_request(access_token="test_access_token", host_ip=test_host_ip, app_instance_id="1",
        #                               image_id="98920865-8c34-4f32-a166-f7c06775a34a"))

        # response = stub.queryVmImage(
        #     make_delete_image_request(access_token="test_access_token", host_ip=test_host_ip, app_instance_id="1",
        #                               image_id="f514d88e-9c1f-4302-bbbc-6d045dc2a704"))

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
