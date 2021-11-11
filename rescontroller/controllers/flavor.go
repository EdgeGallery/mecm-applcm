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

// flavor Controller
type FlavorController struct {
	BaseController
}

// @Title Health Check
// @Description perform health check
// @Success 200 ok
// @Failure 400 bad request
// @router /health [get]
func (c *FlavorController) HealthCheck() {
	_, _ = c.Ctx.ResponseWriter.Write([]byte("ok"))
}

// @Title Create Flavor
// @Description Create Flavor
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   body        body    models.Flavor   true      "The flavor information"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/flavor [post]
func (c *FlavorController) CreateFlavor() {
	log.Info("Create flavor request received.")

	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	var flavor models.Flavor
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &flavor)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}
	response, err := adapter.CreateFlavor(flavor, hostIp, accessToken, tenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeInternalServer)
		return
	}
	c.handleLoggingForSuccessV1(clientIp, util.CreateFlavorSuccess)
}

// @Title Query Flavor
// @Description Query Flavor
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   flavorId      path 	     string	true   "flavorId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/flavor/flavorId [get]
func (c *FlavorController) QueryFlavor() {
	log.Info("Query flavor request received.")
	var flavorId = ""

	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	if c.IsIdAvailable(util.FlavorId) {
		flavorId = c.GetId(util.FlavorId)
	}

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}
	response, err := adapter.QueryFlavor(hostIp, accessToken, tenantId, flavorId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeInternalServer)
		return
	}
	c.handleLoggingForSuccessV1(clientIp, "Query flavor is successful")
}

// @Title Delete Flavor
// @Description Delete Flavor
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   flavorId      path 	     string	true   "flavorId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/flavor/flavorId [get]
func (c *FlavorController) DeleteFlavor() {
	log.Info("Delete flavor by flavor id request received.")

	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	flavorId := c.GetId(util.FlavorId)
	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}
	_, err = adapter.DeleteFlavor(hostIp, accessToken, tenantId, flavorId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.handleLoggingForSuccess(nil, clientIp, util.DeleteFlavorSuccess)
}