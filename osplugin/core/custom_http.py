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

from glanceclient import exc
from glanceclient.common.http import HTTPClient
from glanceclient.common.http import SessionClient
from keystoneauth1 import exceptions as ksa_exc

from core.log import logger

LOG = logger
USER_AGENT = 'python-glanceclient'
REQ_ID_HEADER = 'X-OpenStack-Request-ID'


class CustomSessionClient(SessionClient):
    """
    自定义 SessionClient 取消 headers encode , 分片下载时 Range头encode 后返回416
    """

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
    """
    get_http_client
    """
    if session:
        return CustomSessionClient(session, **kwargs)
    elif endpoint:
        return HTTPClient(endpoint, **kwargs)
    raise AttributeError('Constructing a client must contain either an '
                         'endpoint or a session')
