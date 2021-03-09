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
func (c *BaseController) handleLoggingForError(clientIp string, code int, errMsg string) {
	c.writeErrorResponse(errMsg, code)
	log.Info("Response message for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}

// Write error response
func (c *BaseController) writeErrorResponse(errMsg string, code int) {
	log.Error(errMsg)
	c.writeResponse(errMsg, code)
}

// Write response
func (c *BaseController) writeResponse(msg string, code int) {
	c.Data["json"] = msg
	c.Ctx.ResponseWriter.WriteHeader(code)
	c.ServeJSON()
}

func (c *BaseController) isPermitted(accessToken, clientIp string) (string, error) {
	var tenantId = ""
	var err error

	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		c.handleLoggingForError(clientIp, util.BadRequest, util.RequestBodyTooLarge)
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
		if err.Error() == util.Forbidden {
			c.handleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
		} else {
			c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		}
		return tenantId, err
	}
	return tenantId, nil
}

// Get app Instance Id
func (c *BaseController) getTenantId(clientIp string) (string, error) {
	tenantId := c.Ctx.Input.Param(":tenantId")
	err := util.ValidateUUID(tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, "Tenant id is invalid")
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
		c.handleLoggingForError(clientIp, util.BadRequest, "App instance is invalid")
		return "", err
	}
	return appInsId, nil
}

// Get app info record
func (c *BaseController) getAppInfoRecord(appInsId string, clientIp string) (*models.AppInfoRecord, error) {
	appInfoRecord := &models.AppInfoRecord{
		AppInsId: appInsId,
	}

	readErr := c.Db.ReadData(appInfoRecord, util.AppInsId)
	if readErr != nil {
		c.handleLoggingForError(clientIp, util.StatusNotFound,
			"App info record does not exist in database")
		return nil, readErr
	}
	return appInfoRecord, nil
}

// Get vim name
func (c *BaseController) getVim(clientIp string, hostIp string) (string, error) {

	// Get VIM from host table based on hostIp, TBD
	vim := ""

	// Default to k8s for backward compatibility
	if vim == "" {
		log.Info("Setting plugin to default value which is k8s, as no VIM is mentioned explicitly")
		vim = "k8s"
	}
	return vim, nil
}

func (c *BaseController) getPluginAdapter(deployType, clientIp string, vim string) (*pluginAdapter.PluginAdapter,
	error) {
	var pluginInfo string

	switch deployType {
	case "helm":
		pluginInfo = util.GetPluginInfo(vim)
	default:
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.DeployTypeIsNotHelmBased)
		return nil, errors.New(util.DeployTypeIsNotHelmBased)
	}

	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
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
		c.handleLoggingForError(clientIp, util.BadRequest, "HostIp address is invalid from url")
		return "", err
	}
	return hostIp, nil
}

// Handle logging for k8s
func (c *BaseController) handleLoggingK8s(clientIp string, errorString string) {
	if strings.Contains(errorString, util.Forbidden) {
		c.handleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
	} else if strings.Contains(errorString, util.AccessTokenIsInvalid) {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
	} else {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, errorString)
	}
}

// Delete app info record
func (c *BaseController) deleteAppInfoRecord(appInsId string) error {
	appInfoRecord := &models.AppInfoRecord{
		AppInsId: appInsId,
	}

	err := c.Db.DeleteData(appInfoRecord, util.AppInsId)
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

	count, err := c.Db.QueryCountForAppInfo("app_info_record", util.TenantId, tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	if count == 0 {
		err = c.Db.DeleteData(tenantRecord, util.TenantId)
		if err != nil {
			c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
			return err
		}
	}
	return nil
}
