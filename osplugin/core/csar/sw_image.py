import json


class SwImageDescription:
    def __init__(self, json_data):
        self.id = json_data['id']
        self.name = json_data['name']
        self.version = json_data['version']
        self.checksum = json_data['checksum']
        self.containerFormat = json_data['containerFormat']
        self.diskFormat = json_data['diskFormat']
        self.minDisk = json_data['minDisk']
        self.minRam = json_data['minRam']
        self.architecture = json_data['architecture']
        self.size = json_data['size']
        self.sw_image = json_data['swImage']
        self.hw_scsi_model = json_data['hw_scsi_model']
        self.hw_disk_bus = json_data['hw_disk_bus']
        self.operation_system = json_data['operationSystem']
        self.supported_virtualization_environment = json_data['supportedVirtualizationEnvironment']


def get_sw_image_desc_list(path):
    result = []
    with open(path, 'r') as sw_image_desc_json_file:
        json_list = json.loads(sw_image_desc_json_file.read())
        for json_data in json_list:
            result.append(SwImageDescription(json_data))
        return result
