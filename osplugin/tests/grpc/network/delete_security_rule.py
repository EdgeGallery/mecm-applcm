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

from internal.resourcemanager.resourcemanager_pb2 import DeleteSecurityGroupRuleRequest
from tests.grpc.client import security_group_stub, test_host_ip, test_tenant_id
from tests.resources.gen_token import test_access_token

delete_security_rule = DeleteSecurityGroupRuleRequest(
    accessToken=test_access_token,
    hostIp=test_host_ip,
    tenantId=test_tenant_id,
    securityGroupRuleId='c5ee31ee-d47f-4c6e-960c-e0078504dda1'
)

if __name__ == '__main__':
    resp = security_group_stub.deleteSecurityGroupRule(delete_security_rule)
    print(resp)
