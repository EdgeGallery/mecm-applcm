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


def get_sw_image_desc_list(path):
    """
    读取镜像描述文件
    param: path 镜像描述文件路径
    return: 镜像描述文件列表
    """
    with open(path, 'r') as sw_image_desc_json_file:
        return json.loads(sw_image_desc_json_file.read())
