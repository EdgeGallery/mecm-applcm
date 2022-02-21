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
import os
import configparser

base_dir = os.getenv('BASE_DIR', '.')

conf = configparser.RawConfigParser()
conf.read(base_dir + '/config.ini')

env = conf.get('default', 'env')

ssl_enabled = os.getenv('ENABLE_SSL', conf.get('default', 'enable_ssl')) != 'false'

listen_ip = os.getenv('LISTEN_IP', '[::]')

log_dir = os.getenv("LOG_DIR", base_dir + '/log')
private_key_certificate_chain_pairs = (
    base_dir + '/ssl/server_tls.key',
    base_dir + '/ssl/server_tls.crt',
)
root_certificates = base_dir + '/ssl/ca.crt'

_JWT_PUBLIC_KEY_DEF = '-----BEGIN PUBLIC KEY-----\n' \
                 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmesVPVWJmsRIzitiu6rs\n' \
                 'bbIfBbt3t97qiJ4yQH1bCHpYu+ab+Xs5heSnfFjHH8nZDAR0n2zvliztIvTDwl/2\n' \
                 'NF9+/loFvmQMrSv1dQQCOBc5qZ5rw/0o7Cq3buXHHJ7CwP0NnreK4N1sZ4oLBTQQ\n' \
                 'e4ERkXhiBNVxAmnbgl7QuhemMV0gxPABSLLKGIrzYR7n8OFDCuSAyOcaoyxJihA/\n' \
                 '4Tkh+Vs82tWlFglV7UxtU2+3e5sN9u/TJ5J3qRZnYq/NWymix9RRD53vp1RGUMCg\n' \
                 'kT40wK5Ak9qdVkr82JTR1g7AtXm9SxlgMNr0rD35WSacioFwECWun+VPL4FyzZ30\n' \
                 'BwIDAQAB\n'\
                 '-----END PUBLIC KEY-----'

jwt_public_key = os.getenv('JWT_PUBLIC_KEY', _JWT_PUBLIC_KEY_DEF)

db_user = os.getenv('DB_USER', conf.get('postgres', 'username'))
db_password = os.getenv('DB_PASSWORD', conf.get('postgres', 'password'))
db_host = os.getenv('DB_HOST', conf.get('postgres', 'host'))
db_port = int(os.getenv('DB_PORT', conf.get('postgres', 'port')))
db_name = os.getenv('DB_NAME', conf.get('postgres', 'database'))

_SERVER_CA_VERIFY = os.getenv('SERVER_CA_VERIFY_DIR', 'false')
if _SERVER_CA_VERIFY == 'false':
    _SERVER_CA_VERIFY = False
elif _SERVER_CA_VERIFY == 'true':
    _SERVER_CA_VERIFY = True
server_ca_verify = _SERVER_CA_VERIFY

image_push_url = os.getenv('IMAGE_PUSH_URL', conf.get('default', 'image_push_url'))
