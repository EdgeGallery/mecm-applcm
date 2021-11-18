/*
 * Copyright 2021 Huawei Technologies Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package controllers

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"rescontroller/models"
	"rescontroller/util"
	"unsafe"
)

// security group Controller
type SecurityGroupController struct {
	BaseController
}

// @Title Create Security Group
// @Description Create Security Group
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   body          body    models.SecurityGroup   true      "The security group information"
// @Success 200 ok
// @Failure 400 bad request
// @router "/tenants/:tenantId/hosts/:hostIp/securityGroup" [post]
func (c *SecurityGroupController) CreateSecurityGroup() {
	log.Info("Create security group request received.")

	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	var securityGroup models.SecurityGroup
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &securityGroup)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}
	response, err := adapter.CreateSecurityGroup(securityGroup, hostIp, accessToken, tenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.SendResponse(clientIp, response, "Create security group is successful")
}

// @Title Query Security Group
// @Description Query Security Group
// @Param   access_token          header     string true   "access token"
// @Param   tenantId              path 	     string	true   "tenantId"
// @Param   hostIp                path 	     string	true   "hostIp"
// @Param   securityGroupId       path 	     string	true   "securityGroupId"
// @Success 200 ok
// @Failure 400 bad request
// @router "/tenants/:tenantId/hosts/:hostIp/securityGroup/:securityGroupId" [get]
func (c *SecurityGroupController) QuerySecurityGroup() {
	log.Info("Query security group request received.")
	var securityGroupdId = ""

	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	if c.IsIdAvailable(util.SecurityGroupId) {
		securityGroupdId = c.GetId(util.SecurityGroupId)
	}

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}

	response, err := adapter.QuerySecurityGroup(hostIp, accessToken, tenantId, securityGroupdId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.SendResponse(clientIp, response, "Query security group is successful")
}

// @Title Delete Security Group
// @Description Delete Security Group
// @Param   access_token          header     string true   "access token"
// @Param   tenantId              path 	     string	true   "tenantId"
// @Param   hostIp                path 	     string	true   "hostIp"
// @Param   securityGroupId       path 	     string	true   "securityGroupId"
// @Success 200 ok
// @Failure 400 bad request
// @router "/tenants/:tenantId/hosts/:hostIp/securityGroup/:securityGroupId" [delete]
func (c *SecurityGroupController) DeleteSecurityGroup() {
	log.Info("Delete security group by security group id request received.")
	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	securityGroupId := c.GetId(util.SecurityGroupId)

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}
	_, err = adapter.DeleteSecurityGroup(hostIp, accessToken, tenantId, securityGroupId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.handleLoggingForSuccess(nil, clientIp, "Delete security group is successful")
}

// @Title Create Security Group rule
// @Description Create Security Group rule
// @Param   access_token          header     string true   "access token"
// @Param   tenantId              path 	     string	true   "tenantId"
// @Param   hostIp                path 	     string	true   "hostIp"
// @Param   securityGroupId       path 	     string	true   "securityGroupId"
// @Param   body          body    models.SecurityGroupRules   true      "The security group rules information"
// @Success 200 ok
// @Failure 400 bad request
// @router "/tenants/:tenantId/hosts/:hostIp/securityGroups/:securityGroupId/securityGroupRules" [post]
func (c *SecurityGroupController) CreateSecurityGroupRules() {
	log.Info("Create security group rules request received.")
	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	var securityGroupRules models.SecurityGroupRules
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &securityGroupRules)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}
	response, err := adapter.CreateSecurityGroupRules(securityGroupRules, hostIp, accessToken, tenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.SendResponse(clientIp, response, "Create security group rule is successful")
}

// @Title Query Security Group rule
// @Description Query Security Group rule
// @Param   access_token          header     string true   "access token"
// @Param   tenantId              path 	     string	true   "tenantId"
// @Param   hostIp                path 	     string	true   "hostIp"
// @Param   securityGroupId       path 	     string	true   "securityGroupId"
// @Success 200 ok
// @Failure 400 bad request
// @router "/tenants/:tenantId/hosts/:hostIp/securityGroups/:securityGroupId/securityGroupRules" [get]
func (c *SecurityGroupController) QuerySecurityGroupRules() {
	log.Info("Query security group rules request received.")
	var securityGroupdId = ""

	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	if c.IsIdAvailable(util.SecurityGroupId) {
		securityGroupdId = c.GetId(util.SecurityGroupId)
	}

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}
	response, err := adapter.QuerySecurityGroupRules(hostIp, accessToken, tenantId, securityGroupdId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.SendResponse(clientIp, response, "Query security group rule is successful")
}

// @Title Delete Security Group rule
// @Description Delete Security Group rule
// @Param   access_token          header     string true   "access token"
// @Param   tenantId              path 	     string	true   "tenantId"
// @Param   hostIp                path 	     string	true   "hostIp"
// @Param   securityGroupId       path 	     string	true   "securityGroupId"
// @Param   securityGroupRuleId   path 	     string	true   "securityGroupRuleId"
// @Success 200 ok
// @Failure 400 bad request
// @router "/tenants/:tenantId/hosts/:hostIp/securityGroup/:securityGroupId/securityGroupRules/:securityGroupRuleId" [delete]
func (c *SecurityGroupController) DeleteSecurityGroupRules() {
	log.Info("Delete security group rules by security group rules id request received.")
	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	securityGroupRuleId := c.GetId(":securityGroupRuleId")
	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}
	_, err = adapter.DeleteSecurityGroupRule(hostIp, accessToken, tenantId, securityGroupRuleId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.handleLoggingForSuccess(nil, clientIp, "Delete security group rule is successful")
}
