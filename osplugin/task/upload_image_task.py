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
import threading
from queue import Queue

from core import openstack_utils
from core.log import logger

LOG = logger


class ImageUploadThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.queue = Queue(maxsize=1024)

    def run(self):
        while True:
            data = self.queue.get()
            _upload_image(data['image_id'], data['file'], data['host_ip'])
            self.queue.task_done()

    def put(self, data):
        self.queue.put(data)


thread = ImageUploadThread()


def _upload_image(image_id, file, host_ip):
    glance_client = openstack_utils.create_glance_client(host_ip=host_ip)
    with open(file) as image_file:
        glance_client.images.upload(image_id=image_id, image_data=image_file)


def add_job(image_id, file, host_ip):
    thread.put({image_id, file, host_ip})


def start():
    thread.start()
    LOG.info('start image upload task')
