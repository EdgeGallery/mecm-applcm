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
	"rescontroller/pkg/pluginAdapter"
	"rescontroller/util"
	"unsafe"
)

// network Controller
type NetworkController struct {
	BaseController
}

// @Title Add network
// @Description Add network
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   body        body    models.Network   true      "The mec host information"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/networks [post]
func (c *NetworkController) CreateNetwork() {
	log.Info("Create network request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	tenantId, err := c.isPermitted([]string{util.MecmTenantRole, util.MecmAdminRole}, accessToken, clientIp)
	if err != nil {
		return
	}
	defer util.ClearByteArray(bKey)
	hostIp, vim, err := c.GetInputParameters(clientIp)
	if err != nil {
		return
	}
	var network models.Network
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &network)
	if err != nil {
		c.writeErrorResponse(err.Error(), util.BadRequest)
		return
	}
	err = c.ValidateBodyParams(network, clientIp)
	if err != nil{
		return
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedGetPlugin)
		return
	}

	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	response, err := adapter.CreateNetwork(network, hostIp, accessToken, tenantId)
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
	c.handleLoggingForSuccessV1(clientIp, util.CreateNetworkSuccess)
}

// @Title Query Network
// @Description Query Network
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   networkId      path 	 string	true   "networkId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/networks/networkId [get]
func (c *NetworkController) QueryNetwork() {
	log.Info("Query network request received.")
	var networkId = ""

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))

	tenantId, err := c.isPermitted([]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole}, accessToken, clientIp)
	if err != nil {
		return
	}
	defer util.ClearByteArray(bKey)
	hostIp, vim, err := c.GetInputParameters(clientIp)
	if err != nil {
		return
	}
	if c.IsIdAvailable(util.NetworkId) {
		networkId, err = c.GetId(util.NetworkId, clientIp)
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedGetPlugin)
		return
	}

	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	response, err := adapter.QueryNetwork(hostIp, accessToken, tenantId, networkId)
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
	c.handleLoggingForSuccessV1(clientIp, "Query network is successful")
}

// @Title Delete Network
// @Description Delete Network
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   networkId      path 	     string	true   "networkId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/networks/networkId [get]
func (c *NetworkController) DeleteNetwork() {
	log.Info("Delete network request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))

	tenantId, err := c.isPermitted([]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole}, accessToken, clientIp)
	if err != nil {
		return
	}
	defer util.ClearByteArray(bKey)
	hostIp, vim, err := c.GetInputParameters(clientIp)
	if err != nil {
		return
	}
	networkId, err := c.GetId(util.NetworkId, clientIp)

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedGetPlugin)
		return
	}

	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.DeleteNetwork(hostIp, accessToken, tenantId, networkId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.handleLoggingForSuccess(nil, clientIp, util.DeleteNetworkSuccess)
}

func (c *NetworkController) ValidateBodyParams (network models.Network, clientIp string) error {

	// add validation code here
	for _, subnet := range network.Subnets {
		err := util.ValidateIpv4Address(subnet.GatewayIp)
		if err != nil {
			c.HandleLoggingForError(clientIp, util.BadRequest, "subnet.GatewayIp address is invalid")
			return err
		}
		for _, sub := range subnet.AllocationPools {
			err := util.ValidateIpv4Address(sub.Start)
			if err != nil {
				c.HandleLoggingForError(clientIp, util.BadRequest, "sub.Start address is invalid")
				return err
			}
			err1 := util.ValidateIpv4Address(sub.End)
			if err1 != nil {
				c.HandleLoggingForError(clientIp, util.BadRequest, "sub.End address is invalid")
				return err
			}
		}
	}

	name, err := util.ValidateName(network.Name, util.NameRegex)
	if err != nil || !name {
		c.HandleLoggingForError(clientIp, util.BadRequest, "name is invalid")
		return err
	}
	return nil
}