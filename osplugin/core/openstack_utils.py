# -*- coding: utf-8 -*-
import re

from heatclient import client
from heatclient.exc import HTTPNotFound
from heatclient.common import template_utils
from keystoneauth1 import identity, session
from pony.orm import db_session, commit

import config

RC_FILE_DIR = config.base_dir + '/config'


def create_heat_client(host_ip):
    rc_file_path = RC_FILE_DIR + '/' + host_ip
    rc = RCFile(rc_file_path)

    auth = identity.Password(
        user_domain_name=rc.user_domain_name,
        username=rc.username,
        password=rc.password,
        project_domain_name=rc.project_domain_name,
        project_name=rc.project_name,
        auth_url=rc.auth_url
    )
    sess = session.Session(auth=auth)
    return client.Client('1', session=sess)


class RCFile(object):
    _PATTERN = r'^export (.+)="(.+)"$'

    user_domain_name = 'Default'
    project_domain_name = 'Default'
    username = None
    password = None
    project_name = None
    auth_url = None

    def __init__(self, rc_path):
        with open(rc_path, 'r') as file:
            for line in file.readlines():
                match = re.match(self._PATTERN, line)
                group1 = match.group(1)
                group2 = match.group(2)
                if group1 == 'OS_AUTH_URL':
                    self.auth_url = group2
                elif group1 == 'OS_USERNAME':
                    self.username = group2
                elif group1 == 'OS_PASSWORD':
                    self.password = group2
                elif group1 == 'OS_PROJECT_NAME':
                    self.project_name = group2
                elif group1 == 'OS_PROJECT_DOMAIN_NAME':
                    self.project_domain_name = group2
                elif group1 == 'OS_USER_DOMAIN_NAME':
                    self.user_domain_name = group2
