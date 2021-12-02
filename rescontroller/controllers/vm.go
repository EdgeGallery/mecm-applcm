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

// vm Controller
type VmController struct {
	BaseController
}

// @Title Create Server
// @Description Create Server
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   body          body       models.Server   true      "The server information"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/servers [post]
func (c *VmController) CreateServer() {
	log.Info("Create server request received.")
	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)
	var server models.Server
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &server)
	if err != nil {
		c.writeErrorResponse(err.Error(), util.BadRequest)
		return
	}
	log.Info(server)
	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}

	response, err := adapter.CreateServer(server, hostIp, accessToken, tenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.SendResponse(clientIp, response, "Create server is successful")
}

// @Title Query Server
// @Description Query Server
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   serverId      path 	     string	true   "serverId "
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/servers/:serverId [get]
func (c *VmController) QueryServer() {
	log.Info("Query server request received.")
	var serverId = ""

	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	if c.IsIdAvailable(util.ServerId) {
		serverId, err = c.GetId(util.ServerId, clientIp)
	}

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}

	response, err := adapter.QueryServer(hostIp, accessToken, tenantId, serverId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.SendResponse(clientIp, response, "Query server is successful")
}

// @Title Operate Server
// @Description Operate Server
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   serverId      path 	     string	true   "serverId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/servers/:serverId [post]
func (c *VmController) OperateServer() {
	log.Info("Operate server request received.")

	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	var operateServer models.OperateServer
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &operateServer)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}

	name, err := util.ValidateName(operateServer.Createimage.Name, util.NameRegex)
	if err != nil || !name {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Operator server create image name is invalid")
		return
	}
	serverId, err := c.GetId(util.ServerId, clientIp)

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}
	response, err := adapter.OperateServer(operateServer, hostIp, accessToken, tenantId, serverId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.SendResponse(clientIp, response, "Operate server is successful")
}

// @Title Delete Server
// @Description Delete Server
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   serverId      path 	     string	true   "serverId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/servers/:serverId [delete]
func (c *VmController) DeleteServer() {
	log.Info("Delete server by server id request received")
	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	serverId, err := c.GetId(util.ServerId,clientIp)

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}
	_, err = adapter.DeleteServer(hostIp, accessToken, tenantId, serverId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}

	c.handleLoggingForSuccess(nil, clientIp, "Delete server is successful")
}

func ValidateBody( server models.Server , clientIp string) error {

	err := util.ValidateUUID(server.Flavor)
	if err != nil {
		return err
	}
	err = util.ValidateUUID(server.Image)
	if err != nil {
		return err
	}
	err = util.ValidateUUID(server.Imageref)
	if err != nil {
		return err
	}

	for _, network := range server.Network {
		err = util.ValidateUUID(network.Network)
		if err != nil {
			return err
		}
		err := util.ValidateIpv4Address(network.FixedIp)
		if err != nil {
			return err
		}
	}
	name, err := util.ValidateName(server.Name, util.NameRegex)
	if err != nil || !name {
		return err
	}
	return nil
}