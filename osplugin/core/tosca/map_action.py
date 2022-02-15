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
import logging

logger = logging.getLogger()


def data_mapping(map_dict, template, properties, **kwargs):
    """

    Args:
        map_dict:
        template:
        properties:
        **kwargs:

    Returns:

    """
    for key, item in template.items():
        sub_data_mapping(map_dict, key, item, properties, **kwargs)


def sub_data_mapping(map_dict, f_key, sub_data, properties, **kwargs):
    """

    Args:
        map_dict:
        f_key:
        sub_data:
        properties:
        **kwargs:

    Returns:

    """
    if f_key in map_dict:
        map_dict[f_key].do_action(sub_data, properties, **kwargs)
    elif isinstance(sub_data, dict):
        for key, item in sub_data.items():
            sub_data_mapping(map_dict, f_key + '.' + key, item, properties, **kwargs)
    elif isinstance(sub_data, list):
        for item in sub_data:
            sub_data_mapping(map_dict, f_key + '.%d', item, properties, **kwargs)
    else:
        logger.debug('skip unknown key %s', f_key)


def set_inputs(properties, inputs, parameters):
    """
    把get_input函数替换为实际值
    Args:
        properties:
        inputs:
        parameters:

    Returns:

    """
    if isinstance(properties, dict):
        for sub_key, sub_value in properties.items():
            if isinstance(sub_value, dict) and 'get_input' in sub_value:
                properties[sub_key] = get_from_inputs(sub_value['get_input'], inputs, parameters)
            elif isinstance(sub_value, dict):
                set_inputs(sub_value, inputs, parameters)
    elif isinstance(properties, list):
        for item in properties:
            set_inputs(item, inputs, parameters)


def get_from_inputs(key, inputs, parameters):
    """
    获取根据参数名称获取参数值
    如果没有传入参数值，则从默认值中获取
    Args:
        key: 参数名称
        inputs: 定义参数的dict，包含默认值
        parameters: 参数值列表

    Returns:

    """
    if parameters and key in parameters:
        return parameters[key]
    default_input = inputs.get(key, {'default': None})
    return default_input['default']


class BaseAction(object):
    """
    描述映射时的行为
    """

    def __init__(self, key, skip_value=None):
        """
        指定映射目标
        Args:
            key:
        """
        self.key = key
        self.skip_value = skip_value

    def do_action(self, data, properties, **kwargs):
        """
        执行映射动作
        Args:
            data: 映射元数据
            properties: 目标
            **kwargs:

        Returns:

        """
        pass


class SetAction(BaseAction):
    """
    把一个字段映射到目标字段
    """

    def do_action(self, data, properties, **kwargs):
        if self.skip_value == data:
            return
        properties[self.key] = data


class MapAction(BaseAction):
    def __init__(self, key, map_dict: dict, skip_value=None):
        super().__init__(key, skip_value)
        self.map_dict = map_dict

    def do_action(self, data, properties, **kwargs):
        if data == self.skip_value:
            return
        properties[self.key] = {}
        data_mapping(self.map_dict, data, properties[self.key], **kwargs)


class AppendAction(BaseAction):
    def __init__(self, key, func, skip_value=None):
        super().__init__(key, skip_value)
        self.func = func

    def do_action(self, data, properties, **kwargs):
        if data == self.skip_value:
            return
        map_item = self.func(data, **kwargs)
        if self.key not in properties:
            properties[self.key] = []
        properties[self.key].append(map_item)


class FunctionAction(BaseAction):
    """
    把一个字段映射到目标函数
    """

    def __init__(self, key, func, skip_value=None):
        super().__init__(key, skip_value)
        self.func = func

    def do_action(self, data, properties, **kwargs):
        if data == self.skip_value:
            return
        properties[self.key] = self.func(data, **kwargs)
