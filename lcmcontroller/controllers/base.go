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
	"bufio"
	"errors"
	"github.com/astaxie/beego"
	log "github.com/sirupsen/logrus"
	"lcmcontroller/models"
	"lcmcontroller/pkg/dbAdapter"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"os"
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

func (c *BaseController) HandleForErrorCode(clientIp string, code int, errMsg string, errCode int) {
	errConent := &models.ReturnResponse{
		Data:    nil,
		RetCode: errCode,
		Message: errMsg,
		Params:  nil,
	}
	c.writeErrorResponseV2(errConent, code)
	log.Info(util.ResponseForClient + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}

// Write error response
func (c *BaseController) writeErrorResponse(errMsg string, code int) {
	log.Error(errMsg)
	c.writeResponse(errMsg, code)
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

// Get app Instance Id
func (c *BaseController) GetTenantId(clientIp string) (string, error) {
	tenantId := c.Ctx.Input.Param(":tenantId")
	err := util.ValidateUUID(tenantId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Tenant id is invalid")
		return "", err
	}
	return tenantId, nil
}

// Get app Instance Id
func (c *BaseController) IsTenantAvailable() bool {
	tenantId := c.Ctx.Input.Param(":tenantId")
	return tenantId != ""
}

// Get app Instance Id
func (c *BaseController) GetAppInstId(clientIp string) (string, error) {
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
func (c *BaseController) GetAppPackageRecord(appPkgId string, tenantId string, clientIp string) (*models.AppPackageRecord, error) {
	appPkgRecord := &models.AppPackageRecord{
		AppPkgId: appPkgId,
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
		PkgHostKey: appPkgId + hostIp,
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
func (c *BaseController) GetVim(clientIp, hostIp, tenantId string) (string, error) {

	mecHostInfoRec, err := c.GetMecHostInfoRecord(hostIp, clientIp, tenantId)
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

func (c *BaseController) GetPluginAdapter(_, clientIp string, vim string) (*pluginAdapter.PluginAdapter,
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
func (c *BaseController) DeleteAppInfoRecord(appInsId string) error {
	appInfoRecord := &models.AppInfoRecord{
		AppInstanceId: appInsId,
	}

	err := c.Db.DeleteData(appInfoRecord, util.AppInsId)
	if err != nil {
		c.HandleLoggingForError(appInsId, util.StatusInternalServerError, err.Error())
		return err
	}
	return nil
}

// Delete app package record
func (c *BaseController) DeleteAppPackageRecord(appPkgId string, tenantId string) error {
	appPkgRecord := &models.AppPackageRecord{
		AppPkgId: appPkgId,
	}

	err := c.Db.DeleteData(appPkgRecord, util.AppPkgId)
	if err != nil {
		c.HandleLoggingForError(appPkgId, util.StatusInternalServerError, err.Error())
		return err
	}
	return nil
}

// Delete app package host record
func (c *BaseController) DeleteAppPackageHostRecord(hostIp, appPkgId, tenantId string) error {
	appPkgHostRecord := &models.AppPackageHostRecord{
		PkgHostKey: appPkgId + hostIp,
	}

	err := c.Db.DeleteData(appPkgHostRecord, util.PkgHostKey)
	if err != nil {
		c.HandleLoggingForError(hostIp, util.StatusInternalServerError, err.Error())
		return err
	}
	return nil
}

// Delete tenant record
func (c *BaseController) DeleteTenantRecord(clientIp, tenantId string) error {
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
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteDataFailed)
			return err
		}
	}
	return nil
}

// Get mec host info record
func (c *BaseController) GetMecHostInfoRecord(hostIp, clientIp, tenantId string) (*models.MecHost, error) {

	mecHostInfoRecord := &models.MecHost{
		MecHostId: hostIp + util.UnderScore + tenantId,
	}

	readErr := c.Db.ReadData(mecHostInfoRecord, util.HostId)
	if readErr != nil {
		mecHostInfoRecord = &models.MecHost{
			MechostIp: hostIp,
			Role:      util.MecmAdminRole,
		}
		readErr = c.Db.ReadData(mecHostInfoRecord, util.MecHostIp)
		if readErr != nil {
			c.HandleLoggingForError(clientIp, util.StatusNotFound, util.MecHostRecDoesNotExist)
			return nil, readErr
		}
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

func readMfBytes(mfYaml *os.File) ([]byte, error) {
	scanner := bufio.NewScanner(mfYaml)
	scanner.Split(bufio.ScanLines)
	// This is our buffer now
	var lines []byte

	for scanner.Scan() {
		line := scanner.Text()
		if checkLineStart(line) {
			lines = append(lines, []byte(line)...)
			lines = append(lines, []byte("\n")...)
		}
	}
	return lines, nil
}

func checkLineStart(line string) bool {
	res := false
	res = strings.HasPrefix(line, util.PkgDtlMetadata)
	if res {
		return true
	}
	res = strings.HasPrefix(line, util.PkgDtlAppName)
	if res {
		return true
	}
	res = strings.HasPrefix(line, util.PkgDtlAppId)
	if res {
		return true
	}
	res = strings.HasPrefix(line, util.PkgDtlAppVersion)
	if res {
		return true
	}
	res = strings.HasPrefix(line, util.PkgDtlAppRlsTime)
	if res {
		return true
	}
	res = strings.HasPrefix(line, util.PkgDtlAppType)
	if res {
		return true
	}
	res = strings.HasPrefix(line, util.PkgDtlAppClass)
	if res {
		return true
	}
	res = strings.HasPrefix(line, util.PkgDtlAppDescription)
	if res {
		return true
	}
	return res
}

// Get user name
func (c *BaseController) getUserName(clientIp string) (string, error) {
	userName := c.Ctx.Request.Header.Get("name")
	if userName != "" {
		name, err := util.ValidateUserName(userName, util.NameRegex)
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

func (c *BaseController) validateCredentials(clientIp, userName, key string) error {

	edgeAuthInfoRec := &models.EdgeAuthenticateRec{
		Name: userName,
	}

	readErr := c.Db.ReadData(edgeAuthInfoRec, "name")
	if readErr != nil {
		log.Info("Query user with error: ", readErr.Error())
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

// Validate token and credentials
func (c *BaseController) ValidateTokenAndCredentials(accessToken, clientIp, tenantId string) error {
	name, key, err := c.GetUserNameAndKey(clientIp)
	if err != nil {
		return err
	}

	if accessToken != "" {
		err = util.ValidateAccessToken(accessToken,
			[]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole}, tenantId)
		if err != nil {
			c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
			return err
		}
	} else {
		if name != "" && key != "" {
			err = c.validateCredentials(clientIp, name, key)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Get username and key
func (c *BaseController) GetUserNameAndKey(clientIp string) (name, key string, err error) {
	name, err = c.GetUserName(clientIp)
	if err != nil {
		return name, key, err
	}

	key, err = c.GetKey(clientIp)
	if err != nil {
		return name, key, err
	}
	return name, key, err
}

// Get user name
func (c *BaseController) GetUserName(clientIp string) (string, error) {
	userName := c.Ctx.Request.Header.Get("name")
	if userName != "" {
		name, err := util.ValidateUserName(userName, util.NameRegex)
		if err != nil || !name {
			c.HandleLoggingForError(clientIp, util.BadRequest, util.UserNameOrKeyInvalid)
			return "", errors.New(util.UserNameOrKeyInvalid)
		}
	}
	return userName, nil
}

// Get key
func (c *BaseController) GetKey(clientIp string) (string, error) {
	key := c.Ctx.Request.Header.Get("key")
	if key != "" {
		keyValid, err := util.ValidateDbParams(key)
		if err != nil || !keyValid {
			c.HandleLoggingForError(clientIp, util.BadRequest, util.UserNameOrKeyInvalid)
			return "", errors.New(util.UserNameOrKeyInvalid)
		}
	}
	return key, nil
}

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

func HandleStatus(status string) string {
	if strings.ToLower(status) == "uploading" {
		return "Distributing"
	} else if strings.ToLower(status) == "uploaded" {
		return "Distributed"
	}
	return status
}

func (c *BaseController) GetPluginAndClient(clientIp, packageId, tenantId, hostIp string) (string,
	pluginAdapter.ClientIntf, error) {
	appPkgRecord, err := c.GetAppPackageRecord(packageId, tenantId, clientIp)
	if err != nil {
		return "", nil, err
	}

	appPkgHostRecord, err := c.getAppPackageHostRecord(hostIp, appPkgRecord.PackageId, appPkgRecord.TenantId, clientIp)
	if err != nil {
		return "", nil, err
	}

	vim, err := c.GetVim(clientIp, appPkgHostRecord.HostIp, appPkgHostRecord.TenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeGetVimFailed)
		return "", nil, err
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedGetPlugin)
		return "", nil, err
	}
	return pluginInfo, client, nil
}
