# -*- coding: utf-8 -*-
import re

from heatclient import client
from heatclient.exc import HTTPNotFound
from heatclient.common import template_utils
from keystoneauth1 import identity, session
from pony.orm import db_session, commit
from novaclient import client as nova_client
from glanceclient import client as glance_client
import yaml
import config
from core.CustomGlanceClient import CustomGlanceClient

RC_FILE_DIR = config.base_dir + '/config'


def get_rc(host_ip):
    rc_file_path = RC_FILE_DIR + '/' + host_ip
    return RCFile(rc_file_path)


def get_auth(host_ip):
    rc = get_rc(host_ip)
    return identity.Password(
        user_domain_name=rc.user_domain_name,
        username=rc.username,
        password=rc.password,
        project_domain_name=rc.project_domain_name,
        project_name=rc.project_name,
        auth_url=rc.auth_url
    )


def get_session(host_ip):
    return session.Session(auth=get_auth(host_ip))


def create_heat_client(host_ip):
    return client.Client('1', session=get_session(host_ip))


def create_nova_client(host_ip):
    rc = get_rc(host_ip)
    return nova_client.Client('2', session=get_session(host_ip))


def create_glance_client(host_ip):
    asession = get_session(host_ip)
    print(asession.get_token())
    return CustomGlanceClient(session=asession)
    # return glance_client.Client('2', session=get_session(host_ip))


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
