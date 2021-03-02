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
db_host = os.getenv('DB_HOST', '10.21.3.39')
db_port = int(os.getenv('DB_PORT', '5432'))
db_name = os.getenv('DB_NAME', 'osplugindb')

base_dir = os.getenv('BASE_DIR', 'target')
