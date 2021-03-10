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

import hashlib

from glanceclient.common import utils
from glanceclient.v2 import client
from glanceclient.v2.images import Controller
from requests import codes

from core import custom_http


# @author wangy1
class CustomGlanceClient(client.Client):
    def __init__(self, endpoint=None, **kwargs):
        super().__init__(**kwargs)
        self.http_client = custom_http.get_http_client(endpoint=endpoint, **kwargs)
        self.images = CustomController(self.http_client, self.schemas)


def get_chunk_start_end(chunk_num, size, chunk_size):
    if size < chunk_size:
        return 0, size - 1
    else:
        start = chunk_size * (chunk_num - 1)
        if chunk_num == 1:
            return 0, chunk_size - 1
        if chunk_num == size // chunk_size + 1:
            return start, (start + size % chunk_size) - 1
        if chunk_num > size // chunk_size + 1:
            raise Exception("chunk_num oversize!")
    return start, chunk_size * chunk_num - 1


class CustomController(Controller):
    def download_chunk(self, chunk_num, image_size, image_id, do_checksum=True, allow_md5_fallback=False,
                       chunk_size=1024):
        if do_checksum:
            # doing this first to prevent race condition if image record
            # is deleted during the image download
            url = '/v2/images/%s' % image_id
            resp, image_meta = self.http_client.get(url)
            meta_checksum = image_meta.get('checksum', None)
            meta_hash_value = image_meta.get('os_hash_value', None)
            meta_hash_algo = image_meta.get('os_hash_algo', None)
        url = '/v2/images/%s/file' % image_id
        start, end = get_chunk_start_end(chunk_num, image_size, chunk_size)
        headers = {
            'Range': 'bytes=' + str(start) + '-' + str(end)
        }
        resp, body = self.http_client.get(url, headers=headers)
        if resp.status_code == codes.no_content:
            return None, resp

        checksum = resp.headers.get('content-md5', None)
        content_length = int(resp.headers.get('content-length', 0))

        check_md5sum = do_checksum
        if do_checksum and meta_hash_value is not None:
            try:
                hasher = hashlib.new(str(meta_hash_algo))
                body = utils.serious_integrity_iter(body,
                                                    hasher,
                                                    meta_hash_value)
                check_md5sum = False
            except ValueError as ve:
                if (str(ve).startswith('unsupported hash type') and
                        allow_md5_fallback):
                    check_md5sum = True
                else:
                    raise

        if do_checksum and check_md5sum:
            if meta_checksum is not None:
                body = utils.integrity_iter(body, meta_checksum)
            elif checksum is not None:
                body = utils.integrity_iter(body, checksum)
            else:
                # NOTE(rosmaita): this preserves legacy behavior to return the
                # image data when checksumming is requested but there's no
                # 'content-md5' header in the response.  Just want to make it
                # clear that we're doing this on purpose.
                pass

        return utils.IterableWithLength(body, content_length), resp
