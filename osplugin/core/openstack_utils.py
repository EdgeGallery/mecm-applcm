# -*- coding: utf-8 -*-
import re


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
