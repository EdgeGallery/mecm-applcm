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


class SwImageDescription:
    """
    镜像描述，从sw_image_desc.json读取并解析
    """
    def __init__(self, json_data):
        self.name = json_data['name']
        self.checksum = json_data['checksum']
        self.container_format = json_data['containerFormat']
        self.disk_format = json_data['diskFormat']
        self.min_disk = json_data.get('minDisk', None)
        self.min_ram = json_data.get('minRam', None)
        self.architecture = json_data.get('architecture', None)
        self.size = json_data['size']
        self.sw_image = json_data.get('swImage', None)
        self.hw_scsi_model = json_data.get('hw_scsi_model', None)
        self.hw_disk_bus = json_data.get('hw_disk_bus', None)
        self.operating_system = json_data.get('operatingSystem', None)
        self.supported_virtualization_environment = \
            json_data.get('supportedVirtualizationEnvironment', None)


def get_sw_image_desc_list(path):
    """
    读取镜像描述文件
    param: path 镜像描述文件路径
    return: 镜像描述文件列表
    """
    result = []
    with open(path, 'r') as sw_image_desc_json_file:
        json_list = json.loads(sw_image_desc_json_file.read())
        for json_data in json_list:
            result.append(SwImageDescription(json_data))
        return result
