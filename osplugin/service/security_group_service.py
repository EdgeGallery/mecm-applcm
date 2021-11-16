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
from internal.resourcemanager import resourcemanager_pb2_grpc


class SecurityGroupService(resourcemanager_pb2_grpc.SecurityGroupManagerServicer):
    """

    """

    def createSecurityGroup(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        pass

    def deleteSecurityGroup(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        pass

    def querySecurityGroup(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        pass

    def createSecurityGroupRule(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        pass

    def deleteSecurityGroupRule(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        pass

    def querySecurityGroupRule(self, request, context):
        """

        Args:
            request:
            context:

        Returns:

        """
        pass
