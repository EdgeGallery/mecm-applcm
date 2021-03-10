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

enable_ssl = False
if os.getenv('ENABLE_SSL', 'false') == 'true':
    enable_ssl = True

listen_ip = os.getenv('LISTEN_IP', '[::]')

private_key_certificate_chain_pairs = ['', '']
root_certificates = []
require_client_auth = False

_JWT_PUBLIC_KEY_DEF = ''
jwt_public_key = os.getenv('JWT_PUBLIC_KEY', _JWT_PUBLIC_KEY_DEF)

db_user = os.getenv('DB_USER', 'osplugin')
db_password = os.getenv('DB_PASSWORD', 'LH@21cn.com')
db_host = os.getenv('DB_HOST', '127.0.0.1')
db_port = int(os.getenv('DB_PORT', '5432'))
db_name = os.getenv('DB_NAME', 'osplugindb')

base_dir = os.getenv('BASE_DIR', 'target')
# default chunk_size 1M
chunk_size = os.getenv("IMAGE_CHUNK_SIZE", 1024 * 1024 * 1)
