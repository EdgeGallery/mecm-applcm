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
	"errors"
	"github.com/astaxie/beego"
	log "github.com/sirupsen/logrus"
	"rescontroller/models"
	"rescontroller/pkg/dbAdapter"
	"rescontroller/pkg/pluginAdapter"
	"rescontroller/util"
	"strings"
)

// Base Controller
type BaseController struct {
	beego.Controller
	Db dbAdapter.Database
}

// To display log for received message
func (c *BaseController) displayReceivedMsg(clientIp string) {
	log.Info(util.ResponseForClient + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "]")
}

// Handled logging for error case
func (c *BaseController) HandleLoggingForError(clientIp string, code int, errMsg string) {
	c.writeErrorResponse(errMsg, code)
	log.Info(util.ResponseForClient + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}

// Write error response
func (c *BaseController) writeErrorResponse(errMsg string, code int) {
	log.Error(errMsg)
	c.writeResponse(errMsg, code)
}

func (c *BaseController) HandleForErrorCode(clientIp string, code int, errMsg string, errCode int) {
	errConent := &models.ReturnResponse{
		Data:    nil,
		RetCode: errCode,
		Message: errMsg,
		Params: nil,
	}
	c.writeErrorResponseV2(errConent, code)
	log.Info(util.ResponseForClient + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}

func (c *BaseController) writeErrorResponseV2(conent *models.ReturnResponse, code int) {
	c.writeResponse(conent, code)
}

// Write response here
func (c *BaseController) writeResponse(msg interface{}, code int) {
	c.Data["json"] = msg
	c.Ctx.ResponseWriter.WriteHeader(code)
	c.ServeJSON()
}

// Check tenant Id
func (c *BaseController) IsTenantAvailable() bool {
	tenantId := c.Ctx.Input.Param(":tenantId")
	return tenantId != ""
}

// Check id
func (c *BaseController) IsIdAvailable(id string) bool {
	Id := c.Ctx.Input.Param(id)
	return Id != ""
}

// Get tenant Id
func (c *BaseController) GetTenantId(clientIp string) (string, error) {
	tenantId := c.Ctx.Input.Param(":tenantId")
	err := util.ValidateUUID(tenantId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Tenant id is invalid")
		return "", err
	}
	return tenantId, nil
}

// Get tenant Id
func (c *BaseController) GetId(id string, clientIp string) (string, error) {
	Id := c.Ctx.Input.Param(id)
	err := util.ValidateUUID(Id)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, " id is invalid")
		return "", err
	}
	return Id, nil
}

// Get user name
func (c *BaseController) getUserName(clientIp string) (string, error) {
	userName := c.Ctx.Request.Header.Get("name")
	if userName != "" {
		name, err := util.ValidateName(userName, util.NameRegex)
		if err != nil || !name {
			c.HandleLoggingForError(clientIp, util.BadRequest, "username is invalid")
			return "", errors.New("username is invalid")
		}
	}
	return userName, nil
}

// Get key
func (c *BaseController) getKey(clientIp string) (string, error) {
	key := c.Ctx.Request.Header.Get("key")
	if key != "" {
		keyValid, err := util.ValidateDbParams(key)
		if err != nil || !keyValid {
			c.HandleLoggingForError(clientIp, util.BadRequest, "key is invalid")
			return "", errors.New("key is invalid")
		}
	}
	return key, nil
}

// Check user name and key
func (c *BaseController) CheckUserNameAndKey(clientIp string) (string, string, error) {
	name, err := c.getUserName(clientIp)
	if err != nil {
		return name, "", err
	}

	key, err := c.getKey(clientIp)
	if err != nil {
		return name, key, err
	}
	return name, key, nil
}

func (c *BaseController) validateCredentials(clientIp, userName, key string) error {

	edgeAuthInfoRec := &models.EdgeAuthenticateRec{
		Name: userName,
	}

	readErr := c.Db.ReadData(edgeAuthInfoRec, "name")
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			"Edge auth info record does not exist in database")
		return readErr
	}

	if strings.Compare(key, edgeAuthInfoRec.Key) != 0 {
		c.HandleLoggingForError(clientIp, util.BadRequest,
			"Password is not matched")
		return errors.New("invalid credentials")
	}
	return nil
}


// Handled logging for token failure
func (c *BaseController) HandleLoggingForTokenFailure(clientIp, errorString string) {
	if errorString == util.Forbidden {
		c.HandleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
	} else {
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
	}
}


func (c *BaseController) isPermitted(allowedRoles []string, accessToken, clientIp string) (string, error) {
	var tenantId = ""
	var err error

	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.RequestBodyTooLarge)
		return "", errors.New(util.RequestBodyTooLarge)
	}

	if c.IsTenantAvailable() {
		tenantId, err = c.GetTenantId(clientIp)
		if err != nil {
			return tenantId, err
		}
	}

	name, key, err := c.CheckUserNameAndKey(clientIp)
	if err != nil {
		return tenantId, err
	}

	if accessToken != "" {
		err = util.ValidateAccessToken(accessToken, allowedRoles, tenantId)
		if err != nil {
			c.HandleLoggingForTokenFailure(clientIp, err.Error())
			return tenantId, err
		}
	} else {
		if name != "" && key != "" {
			err := c.validateCredentials(clientIp, name, key)
			if err != nil {
				return tenantId, err
			}
		}
	}
	return tenantId, nil
}

// Get host IP from url
func (c *BaseController) GetUrlHostIP(clientIp string) (string, error) {
	hostIp := c.Ctx.Input.Param(":hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Host address is invalid from url")
		return "", err
	}
	return hostIp, nil
}

func handleSuccessReturn(object interface{}, msg string) *models.ReturnResponse {
	result := &models.ReturnResponse{
		Data:    object,
		RetCode: 0,
		Message: msg,
		Params:  nil,
	}
	return result
}

func (c *BaseController) handleLoggingForSuccess(object interface{}, clientIp string, msg string) {
	log.Info("Response for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Success: " + msg + ".]")
	returnContent := handleSuccessReturn(object, msg)
	c.Data["json"] = returnContent
	c.Ctx.ResponseWriter.WriteHeader(util.SuccessCode)
	c.ServeJSON()
}

func (c *BaseController) GetMecHostInfoRecord(hostIp string, clientIp string) (*models.MecHost, error) {
	mecHostInfoRecord := &models.MecHost{
		MecHostId: hostIp,
	}

	readErr := c.Db.ReadData(mecHostInfoRecord, util.HostIp)
	if readErr != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound, util.MecHostRecDoesNotExist, util.ErrCodeHostNotExist)
		return nil, readErr
	}
	return mecHostInfoRecord, nil
}

// Get vim name
func (c *BaseController) GetVim(clientIp string, hostIp string) (string, string, error) {

	mecHostInfoRec, err := c.GetMecHostInfoRecord(hostIp, clientIp)
	if err != nil {
		return "", "", err
	}

	// Get VIM from host table based on hostIp
	vim := mecHostInfoRec.Vim

	// Default to k8s for backward compatibility
	if vim == "" {
		log.Info("Setting plugin to default value which is k8s, as no VIM is mentioned explicitly")
		vim = "k8s"
	}
	tenantId := mecHostInfoRec.TenantId
	return vim, tenantId, nil
}

// Get input parameters for upload configuration
func (c *BaseController) GetInputParameters(clientIp string) (hostIp string, vim string, tenantId string,
	err error) {
	hostIp, err = c.GetUrlHostIP(clientIp)
	if err != nil {
		return hostIp, vim, tenantId, err
	}

	vim, tenantId, err = c.GetVim(clientIp, hostIp)
	if err != nil {
		return hostIp, vim, tenantId, err
	}

	return hostIp, vim, tenantId, nil
}

func (c *BaseController) handleLoggingForSuccessV1(clientIp string, msg string) {
	log.Info("Response for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Success: " + msg + ".]")
}

func (c *BaseController) ValidateAccessTokenAndGetInputParameters(allowedRoles []string) (err error, accessToken, clientIp, hostIp, vim, tenantId string){
	clientIp = c.Ctx.Input.IP()
	err = util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
		return err, accessToken, clientIp, hostIp, vim, tenantId
	}
	c.displayReceivedMsg(clientIp)
	accessToken = c.Ctx.Request.Header.Get(util.AccessToken)
	_, err = c.isPermitted(allowedRoles, accessToken, clientIp)
	if err != nil {
		return err, accessToken, clientIp, hostIp, vim, tenantId
	}
	hostIp, vim, tenantId, err = c.GetInputParameters(clientIp)
	if err != nil {
		return err, accessToken, clientIp, hostIp, vim, tenantId
	}
	return nil, accessToken, clientIp, hostIp, vim, tenantId
}

func (c *BaseController) GetAdapter(clientIp, vim string) (adapter *pluginAdapter.PluginAdapter, err error){
	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedGetPlugin)
		return adapter, err
	}

	adapter = pluginAdapter.NewPluginAdapter(pluginInfo, client)
	return adapter, nil
}

func (c *BaseController) SendResponse(clientIp, response, msg string) {
	_, err := c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeInternalServer)
		return
	}
	c.handleLoggingForSuccessV1(clientIp, msg)
}