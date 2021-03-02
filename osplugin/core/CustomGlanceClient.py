from glanceclient.v2 import client
from glanceclient.v2.images import Controller
import hashlib
from requests import codes
from glanceclient.common import utils
import requests


class CustomGlanceClient(client.Client):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.images = CustomController(self.http_client, self.schemas)


class CustomController(Controller):
    def download_chunk(self, chunk_num, image_id, do_checksum=True, allow_md5_fallback=False, chunk_size=1024):
        if do_checksum:
            # doing this first to prevent race condition if image record
            # is deleted during the image download
            url = '/v2/images/%s' % image_id
            resp, image_meta = self.http_client.get(url)
            meta_checksum = image_meta.get('checksum', None)
            meta_hash_value = image_meta.get('os_hash_value', None)
            meta_hash_algo = image_meta.get('os_hash_algo', None)

        if chunk_num == 1:
            start = 0
        else:
            start = (chunk_num - 1) * chunk_size + 1

        end = chunk_num * chunk_size

        url = '/v2/images/%s/file' % image_id
        headers = {
            'Range': 'bytes=' + str(start) + '-' + str(end)

        }
        print(headers)
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
