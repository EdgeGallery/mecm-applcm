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

import logging

from glanceclient.common.http import HTTPClient
from glanceclient.common.http import SessionClient
from keystoneauth1 import exceptions as ksa_exc
from oslo_utils import importutils

try:
    import json
except ImportError:
    import simplejson as json

from glanceclient import exc

osprofiler_web = importutils.try_import("osprofiler.web")

LOG = logging.getLogger(__name__)
USER_AGENT = 'python-glanceclient'
CHUNKSIZE = 1024 * 64  # 64kB
REQ_ID_HEADER = 'X-OpenStack-Request-ID'
TOKEN_HEADERS = ['X-Auth-Token', 'X-Service-Token']


class CustomSessionClient(SessionClient):

    def __init__(self, session, **kwargs):
        kwargs.setdefault('user_agent', USER_AGENT)
        kwargs.setdefault('service_type', 'image')
        super(CustomSessionClient, self).__init__(session, **kwargs)

    def request(self, url, method, **kwargs):
        headers = kwargs.pop('headers', {})
        if self.global_request_id:
            headers.setdefault(REQ_ID_HEADER, self.global_request_id)

        kwargs['raise_exc'] = False
        data = self._set_common_request_kwargs(headers, kwargs)
        try:
            # NOTE(pumaranikar): To avoid bug #1641239, no modification of
            # headers should be allowed after encode_headers() is called.

            # 取消 headers encode , 分片下载时 Range头encode 后返回416
            resp = super(SessionClient,
                         self).request(url,
                                       method,
                                       headers=headers,
                                       data=data,
                                       **kwargs)
        except ksa_exc.ConnectTimeout as e:
            conn_url = self.get_endpoint(auth=kwargs.get('auth'))
            conn_url = "%s/%s" % (conn_url.rstrip('/'), url.lstrip('/'))
            message = ("Error communicating with %(url)s %(e)s" %
                       dict(url=conn_url, e=e))
            raise exc.InvalidEndpoint(message=message)
        except ksa_exc.ConnectFailure as e:
            conn_url = self.get_endpoint(auth=kwargs.get('auth'))
            conn_url = "%s/%s" % (conn_url.rstrip('/'), url.lstrip('/'))
            message = ("Error finding address for %(url)s: %(e)s" %
                       dict(url=conn_url, e=e))
            raise exc.CommunicationError(message=message)

        return self._handle_response(resp)


def get_http_client(endpoint=None, session=None, **kwargs):
    if session:
        return CustomSessionClient(session, **kwargs)
    elif endpoint:

        return HTTPClient(endpoint, **kwargs)
    else:
        raise AttributeError('Constructing a client must contain either an '
                             'endpoint or a session')
