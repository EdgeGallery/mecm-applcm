import json


class SwImageDescription:
    """
    镜像描述，从sw_image_desc.json读取并解析
    """
    def __init__(self, json_data):
        self.id = json_data.get('id', None)
        self.name = json_data['name']
        self.version = json_data.get('version', None)
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
        self.supported_virtualization_environment = json_data.get('supportedVirtualizationEnvironment', None)


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
