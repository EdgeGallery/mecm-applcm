/*
 * Copyright 2020 Huawei Technologies Co., Ltd.
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
	"errors"
	"github.com/astaxie/beego"
	log "github.com/sirupsen/logrus"
	"lcmcontroller/models"
	"lcmcontroller/pkg/dbAdapter"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"strings"
)

// Base Controller
type BaseController struct {
	beego.Controller
	Db dbAdapter.Database
}

// To display log for received message
func (c *BaseController) displayReceivedMsg(clientIp string) {
	log.Info("Received message from ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "]")
}

// Handled logging for error case
func (c *BaseController) HandleLoggingForError(clientIp string, code int, errMsg string) {
	c.writeErrorResponse(errMsg, code)
	log.Info("Response message for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}

func (c *BaseController) HandleForErrorCode(clientIp string, code int, errMsg string, errCode int) {
	errConent := &models.ReturnResponse{
		Data:    nil,
		RetCode: errCode,
		Message: errMsg,
		Params: nil,
	}
	c.writeErrorResponseV2(errConent, code)
	log.Info("Response message for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}

// Handled logging for error case
func getErrorContent(clientIp string, code int, errMsg string) ([]byte, error){
	result := &models.ReturnResponse{
		Data:    nil,
		RetCode: code,
		Message: errMsg,
		Params: nil,
	}

	resultValue, err := json.Marshal(result)
	return resultValue, err
}

// Write error response
func (c *BaseController) writeErrorResponse(errMsg string, code int) {
	log.Error(errMsg)
	c.writeResponse(errMsg, code)
}

func (c *BaseController) writeErrorResponseV2(conent *models.ReturnResponse, code int) {
	c.writeResponse(conent, code)
}

// Write response
func (c *BaseController) writeResponse(msg interface{}, code int) {
	c.Data["json"] = msg
	c.Ctx.ResponseWriter.WriteHeader(code)
	c.ServeJSON()
}

func (c *BaseController) isPermitted(accessToken, clientIp string) (string, error) {
	var tenantId = ""
	var err error

	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.RequestBodyTooLarge)
		return "", errors.New(util.RequestBodyTooLarge)
	}

	if c.isTenantAvailable() {
		tenantId, err = c.getTenantId(clientIp)
		if err != nil {
			return tenantId, err
		}
	}
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, tenantId)
	if err != nil {
		c.HandleLoggingForTokenFailure(clientIp, err.Error())
		return tenantId, err
	}
	return tenantId, nil
}

// Get app Instance Id
func (c *BaseController) getTenantId(clientIp string) (string, error) {
	tenantId := c.Ctx.Input.Param(":tenantId")
	err := util.ValidateUUID(tenantId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Tenant id is invalid")
		return "", err
	}
	return tenantId, nil
}

// Get app Instance Id
func (c *BaseController) isTenantAvailable() bool {
	tenantId := c.Ctx.Input.Param(":tenantId")
	return tenantId != ""
}

// Get app Instance Id
func (c *BaseController) getAppInstId(clientIp string) (string, error) {
	appInsId := c.Ctx.Input.Param(":appInstanceId")
	err := util.ValidateUUID(appInsId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "App instance is invalid")
		return "", err
	}
	return appInsId, nil
}

// Get app info record
func (c *BaseController) getAppInfoRecord(appInsId string, clientIp string) (*models.AppInfoRecord, error) {
	appInfoRecord := &models.AppInfoRecord{
		AppInstanceId: appInsId,
	}

	readErr := c.Db.ReadData(appInfoRecord, util.AppInsId)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			"App info record does not exist in database")
		return nil, readErr
	}
	return appInfoRecord, nil
}

// Get app package record
func (c *BaseController) getAppPackageRecord(appPkgId string, tenantId string, clientIp string) (*models.AppPackageRecord, error) {
	appPkgRecord := &models.AppPackageRecord{
		AppPkgId: appPkgId + tenantId,
	}

	readErr := c.Db.ReadData(appPkgRecord, util.AppPkgId)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			"App package record does not exist in database")
		return nil, readErr
	}
	return appPkgRecord, nil
}

// Get app package host record
func (c *BaseController) getAppPackageHostRecord(hostIp, appPkgId, tenantId, clientIp string) (*models.AppPackageHostRecord, error) {
	appPkgHostRecord := &models.AppPackageHostRecord{
		PkgHostKey: appPkgId + tenantId + hostIp,
	}

	readErr := c.Db.ReadData(appPkgHostRecord, util.PkgHostKey)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			"App package host record does not exist in database")
		return nil, readErr
	}
	return appPkgHostRecord, nil
}

// Get vim name
func (c *BaseController) getVim(clientIp string, hostIp string) (string, error) {

	mecHostInfoRec, err := c.getMecHostInfoRecord(hostIp, clientIp)
	if err != nil {
		return "", err
	}

	// Get VIM from host table based on hostIp
	vim := mecHostInfoRec.Vim

	// Default to k8s for backward compatibility
	if vim == "" {
		log.Info("Setting plugin to default value which is k8s, as no VIM is mentioned explicitly")
		vim = "k8s"
	}
	return vim, nil
}

func (c *BaseController) getPluginAdapter(_, clientIp string, vim string) (*pluginAdapter.PluginAdapter,
	error) {
	var pluginInfo string

	pluginInfo = util.GetPluginInfo(vim)

	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return nil, err
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	return adapter, nil
}

// Handled logging for success case
func (c *BaseController) handleLoggingForSuccess(clientIp string, msg string) {
	log.Info("Response message for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Success: " + msg + ".]")
}

// Get host IP from url
func (c *BaseController) getUrlHostIP(clientIp string) (string, error) {
	hostIp := c.Ctx.Input.Param(":hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "MecHost address is invalid from url")
		return "", err
	}
	return hostIp, nil
}

// Handle logging
func (c *BaseController) HandleLoggingForFailure(clientIp string, errorString string) {
	if strings.Contains(errorString, util.Forbidden) {
		c.HandleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
	} else if strings.Contains(errorString, util.AccessTokenIsInvalid) {
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
	} else {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, errorString)
	}
}

// Delete app info record
func (c *BaseController) deleteAppInfoRecord(appInsId string) error {
	appInfoRecord := &models.AppInfoRecord{
		AppInstanceId: appInsId,
	}

	err := c.Db.DeleteData(appInfoRecord, util.AppInsId)
	if err != nil {
		return err
	}
	return nil
}

// Delete app package record
func (c *BaseController) deleteAppPackageRecord(appPkgId string, tenantId string) error {
	appPkgRecord := &models.AppPackageRecord{
		AppPkgId: appPkgId + tenantId,
	}

	err := c.Db.DeleteData(appPkgRecord, util.AppPkgId)
	if err != nil {
		return err
	}
	return nil
}

// Delete app package host record
func (c *BaseController) deleteAppPackageHostRecord(hostIp, appPkgId, tenantId string) error {
	appPkgHostRecord := &models.AppPackageHostRecord{
		PkgHostKey: appPkgId + tenantId + hostIp,
	}

	err := c.Db.DeleteData(appPkgHostRecord, util.PkgHostKey)
	if err != nil {
		return err
	}
	return nil
}

// Delete tenant record
func (c *BaseController) deleteTenantRecord(clientIp, tenantId string) error {
	tenantRecord := &models.TenantInfoRecord{
		TenantId: tenantId,
	}

	count, err := c.Db.QueryCountForTable("app_info_record", util.TenantId, tenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeNotFoundInDB)
		return err
	}

	if count == 0 {
		err = c.Db.DeleteData(tenantRecord, util.TenantId)
		if err != nil {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeFailedDeleteData)
			return err
		}
	}
	return nil
}

// Get mec host info record
func (c *BaseController) getMecHostInfoRecord(hostIp string, clientIp string) (*models.MecHost, error) {
	mecHostInfoRecord := &models.MecHost{
		MecHostId: hostIp,
	}

	readErr := c.Db.ReadData(mecHostInfoRecord, util.HostIp)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound, util.MecHostRecDoesNotExist)
		return nil, readErr
	}
	return mecHostInfoRecord, nil
}

// Handled logging for token failure
func (c *BaseController) HandleLoggingForTokenFailure(clientIp, errorString string) {
	if errorString == util.Forbidden {
		c.HandleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
	} else {
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
	}
}