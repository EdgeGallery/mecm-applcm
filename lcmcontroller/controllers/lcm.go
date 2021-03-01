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

// token controller
package controllers

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"lcmcontroller/config"
	"lcmcontroller/models"
	"lcmcontroller/pkg/dbAdapter"
	"mime/multipart"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/astaxie/beego"
	"github.com/ghodss/yaml"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"os"

	log "github.com/sirupsen/logrus"
)

var (
	PackageFolderPath   = "/usr/app/"
	PackageArtifactPath = "/Artifacts/Deployment/"
)

// Lcm Controller
type LcmController struct {
	beego.Controller
	Db dbAdapter.Database
}

// @Title Upload Config
// @Description Upload Config
// @Param	hostIp		 formData 	string	true   "hostIp"
// @Param   configFile   formData   file    true   "config file"
// @Param   access_token header     string  true   "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /configuration [post]
func (c *LcmController) UploadConfig() {
	log.Info("Add configuration request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	_, err = c.isPermitted(accessToken, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	vim, err := c.getVim(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	file, header, err := c.GetFile("configFile")
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.BadRequest, "Upload config file error")
		return
	}

	err = util.ValidateFileExtensionEmpty(header.Filename)
	if err != nil || len(header.Filename) > util.MaxFileNameSize {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.BadRequest,
			"File shouldn't contains any extension or filename is larger than max size")
		return
	}

	err = util.ValidateFileSize(header.Size, util.MaxConfigFile)
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.BadRequest, "File size is larger than max size")
		return
	}

	err = c.validateYamlFile(clientIp, file)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return
	}

	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.UploadConfig(file, hostIp, accessToken)
	util.ClearByteArray(bKey)
	if err != nil {
		errorString := err.Error()
		if strings.Contains(errorString, util.Forbidden) {
			c.handleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
		} else if strings.Contains(errorString, util.AccessTokenIsInvalid) {
			c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		} else {
			c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		}
		return
	}
	c.handleLoggingForSuccess(clientIp, "Upload config is successful")
	c.ServeJSON()
}

// Validate kubeconfig file
func (c *LcmController) validateYamlFile(clientIp string, file multipart.File) error {

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, "Failed to copy file into buffer")
		return err
	}

	_, err := yaml.YAMLToJSON(buf.Bytes())
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, "KubeConfig file validation is failed")
		return err
	}
	return nil
}

// @Title Remove Config
// @Description Remove Config
// @Param   access_token header     string  true   "access token"
// @Param	hostIp		 formData 	string	true   "hostIp"
// @Success 200 ok
// @Failure 400 bad request
// @router /configuration [delete]
func (c *LcmController) RemoveConfig() {
	log.Info("Delete configuration request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, "")
	if err != nil {
		if err.Error() == util.Forbidden {
			c.handleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
		} else {
			c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		}
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	vim, err := c.getVim(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.RemoveConfig(hostIp, accessToken)
	util.ClearByteArray(bKey)
	if err != nil {
		errorString := err.Error()
		if strings.Contains(errorString, util.Forbidden) {
			c.handleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
		} else if strings.Contains(errorString, util.AccessTokenIsInvalid) {
			c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		} else {
			c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		}
		return
	}
	c.handleLoggingForSuccess(clientIp, "Remove config is successful")
	c.ServeJSON()
}

// @Title Instantiate application
// @Description Instantiate application
// @Param   hostIp          formData 	string	true   "hostIp"
// @Param   file            formData    file    true   "file"
// @Param   appName         formData 	string	true   "appName"
// @Param   packageId       formData 	string	false  "packageId"
// @Param   tenantId        path 	string	true   "tenantId"
// @Param   appInstanceId   path 	string	true   "appInstanceId"
// @Param   access_token    header      string  true   "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/:appInstanceId/instantiate [post]
func (c *LcmController) Instantiate() {
	log.Info("Application instantiation request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)

	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	hostIp, appInsId, file, header, tenantId, packageId, err := c.validateToken(accessToken, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	appName, err := c.getAppName(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	err = util.ValidateFileExtensionCsar(header.Filename)
	if err != nil || len(header.Filename) > util.MaxFileNameSize {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.BadRequest,
			"File doesn't contain csar extension or filename is larger than max size")
		return
	}

	appInfoRecord := &models.AppInfoRecord{
		AppInsId: appInsId,
	}

	readErr := c.Db.ReadData(appInfoRecord, util.AppInsId)
	if readErr == nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"App instance info record already exists")
		util.ClearByteArray(bKey)
		return
	}

	packageName, path, fileName, err := c.getPkgName(clientIp, bKey, header, file)
	if err != nil {
		return
	}

	var mainServiceTemplateMf = PackageFolderPath + path + "/" + fileName
	deployType, err := c.getApplicationDeploymentType(mainServiceTemplateMf)
	if err != nil {
		util.ClearByteArray(bKey)
		c.removeCsarFiles(packageName, header, clientIp)
		return
	}

	vim, err := c.getVim(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	artifact, pluginInfo, err := c.getArtifactAndPluginInfo(deployType, path, clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		c.removeCsarFiles(packageName, header, clientIp)
		return
	}

	err, appAuthConfig, acm := processAkSkConfig(appInsId, appName)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		util.ClearByteArray(bKey)
		c.removeCsarFiles(packageName, header, clientIp)
		return
	}

	err = c.insertOrUpdateTenantRecord(clientIp, tenantId)
	if err != nil {
		util.ClearByteArray(bKey)
		c.removeCsarFiles(packageName, header, clientIp)
		return
	}
	err = c.insertOrUpdateAppInfoRecord(appInsId, hostIp, deployType, clientIp, tenantId, packageId)
	if err != nil {
		util.ClearByteArray(bKey)
		c.removeCsarFiles(packageName, header, clientIp)
		return
	}

	err = c.InstantiateApplication(pluginInfo, hostIp, artifact, clientIp, accessToken, appAuthConfig)
	util.ClearByteArray(bKey)
	c.removeCsarFiles(packageName, header, clientIp)
	if err != nil {
		c.handleErrorForInstantiateApp(acm, clientIp, appInsId, tenantId)
		return
	}

	c.handleLoggingForSuccess(clientIp, "Instantiation is successful")
	c.ServeJSON()
}

func (c *LcmController) isPermitted(accessToken, clientIp string) (string, error) {
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

func (c *LcmController) validateToken(accessToken string, clientIp string) (string, string, multipart.File,
	*multipart.FileHeader, string, string, error) {

	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		c.handleLoggingForError(clientIp, util.BadRequest, util.RequestBodyTooLarge)
		return "", "", nil, nil, "", " ", errors.New(util.RequestBodyTooLarge)
	}

	hostIp, appInsId, file, header, tenantId, packageId, err := c.getInputParameters(clientIp)
	if err != nil {
		return "", "", nil, nil, "", " ", err
	}
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, tenantId)
	if err != nil {
		if err.Error() == util.Forbidden {
			c.handleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
		} else {
			c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		}
		return "", "", nil, nil, "", " ", err
	}
	return hostIp, appInsId, file, header, tenantId, packageId, nil
}

// Process Ak Sk configuration
func processAkSkConfig(appInsId, appName string) (error, config.AppAuthConfig, config.AppConfigAdapter) {
	appAuthConfig := config.NewAppAuthCfg(appInsId)
	err := appAuthConfig.GenerateAkSK()
	if err != nil {
		return err, config.AppAuthConfig{}, config.AppConfigAdapter{}
	}

	acm := config.NewAppConfigMgr(appInsId, appName, appAuthConfig)
	err = acm.PostAppAuthConfig()
	if err != nil {
		return err, config.AppAuthConfig{}, config.AppConfigAdapter{}
	}
	return nil, appAuthConfig, acm
}

// Remove CSAR files
func (c *LcmController) removeCsarFiles(packageName string, header *multipart.FileHeader, clientIp string) {
	err := os.RemoveAll(PackageFolderPath + packageName)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"Failed to remove folder")
		return
	}
	err = os.Remove(PackageFolderPath + header.Filename)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"Failed to remove csar file")
		return
	}
}

// @Title Terminate application
// @Description Terminate application
// @Param	tenantId	path 	string	true   "tenantId"
// @Param	appInstanceId   path 	string	true   "appInstanceId"
// @Param       access_token    header  string  true   "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/:appInstanceId/terminate [post]
func (c *LcmController) Terminate() {
	log.Info("Application termination request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))

	tenantId, err := c.isPermitted(accessToken, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appInsId, err := c.getAppInstId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appInfoRecord, err := c.getAppInfoRecord(appInsId, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	vim, err := c.getVim(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.getPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	_, err = adapter.Terminate(appInfoRecord.HostIp, accessToken, appInfoRecord.AppInsId)
	util.ClearByteArray(bKey)
	if err != nil {
		errorString := err.Error()
		c.handleLoggingK8s(clientIp, errorString)
		return
	}

	acm := config.NewAppConfigMgr(appInsId, "", config.AppAuthConfig{})
	err = acm.DeleteAppAuthConfig()
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}

	err = c.deleteAppInfoRecord(appInsId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}

	err = c.deleteTenantRecord(clientIp, tenantId)
	if err != nil {
		return
	}
	c.handleLoggingForSuccess(clientIp, "Termination is successful")
	c.ServeJSON()
}

// @Title App Deployment status
// @Description application deployment status
// @Param	hostIp	     path 	string	true    "hostIp"
// @Param	packageId    path 	string	true    "packageId"
// @Param       access_token header     string  true    "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /hosts/:hostIp/packages/:packageId/status [get]
func (c *LcmController) AppDeploymentStatus() {
	log.Info("Application deployment status request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken,
		[]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole},"")
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}

	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	util.ClearByteArray(bKey)
	hostIp, err := c.getUrlHostIP(clientIp)
	if err != nil {
		return
	}

	packageId, err := c.getUrlPackageId(clientIp)
	if err != nil {
		return
	}

	appInfoRecord := &models.AppInfoRecord{
		HostIp:    hostIp,
		PackageId: packageId,
	}

	response := map[string]bool{"package_deployed": true}
	readErr := c.Db.ReadData(appInfoRecord, "package_id", "host_ip")
	if readErr != nil {
		response["package_deployed"] = false
	}

	responseBody, err := json.Marshal(response)
	if err != nil {
		log.Error("Failed to marshal the request body information")
		return
	}
	_, err = c.Ctx.ResponseWriter.Write(responseBody)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	c.handleLoggingForSuccess(clientIp, "App deployment status is successful")
}

// @Title Health Check
// @Description perform health check
// @Success 200 ok
// @Failure 400 bad request
// @router /health [get]
func (c *LcmController) HealthCheck() {
	_, _ = c.Ctx.ResponseWriter.Write([]byte("ok"))
}

// @Title Query
// @Description perform query operation
// @Param	tenantId	path 	string	true	"tenantId"
// @Param	appInstanceId   path 	string	true	"appInstanceId"
// @Param       access_token    header  string  true    "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/:appInstanceId [get]
func (c *LcmController) Query() {
	log.Info("Application query request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	err = util.ValidateAccessToken(accessToken,
		[]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole}, tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}

	appInsId, err := c.getAppInstId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appInfoRecord, err := c.getAppInfoRecord(appInsId, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	vim, err := c.getVim(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.getPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	response, err := adapter.Query(accessToken, appInsId, appInfoRecord.HostIp)
	util.ClearByteArray(bKey)
	if err != nil {
		res := strings.Contains(err.Error(), "not found")
		if res {
			c.handleLoggingForError(clientIp, util.StatusNotFound, err.Error())
			return
		}
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	c.handleLoggingForSuccess(clientIp, "Query pod statistics is successful")
}

// @Title Query kpi
// @Description perform query kpi operation
// @Param	hostIp          path 	string	true	    "hostIp"
// @Param	tenantId	path 	string	true	    "tenantId"
// @Param       access_token    header  string  true        "access token"
// @Success 200 ok
// @Failure 403 bad request
// @router /tenants/:tenantId/hosts/:hostIp/kpi [get]
func (c *LcmController) QueryKPI() {
	var metricInfo models.MetricInfo
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	err = util.ValidateAccessToken(accessToken,
		[]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole}, tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}
	util.ClearByteArray(bKey)

	prometheusServiceName, prometheusPort := util.GetPrometheusServiceNameAndPort()
	cpuUtilization, err := c.getCpuUsage(prometheusServiceName, prometheusPort, clientIp)
	if err != nil {
		return
	}

	memUsage, err := c.getMemoryUsage(prometheusServiceName, prometheusPort, clientIp)
	if err != nil {
		return
	}

	diskUtilization, err := c.diskUsage(prometheusServiceName, prometheusPort, clientIp)
	if err != nil {
		return
	}
	metricInfo.CpuUsage = cpuUtilization
	metricInfo.MemUsage = memUsage
	metricInfo.DiskUsage = diskUtilization

	metricInfoByteArray, err := json.Marshal(metricInfo)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.MarshalError)
		return
	}

	_, err = c.Ctx.ResponseWriter.Write(metricInfoByteArray)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	c.handleLoggingForSuccess(clientIp, "Query kpi is successful")
}

// @Title Query mep capabilities
// @Description perform query mep capabilities
// @Param	tenantId	path 	string	true	"tenantId"
// @Param	hostIp          path 	string	true	"hostIp"
// @Param	capabilityId    path 	string	false	"capabilityId"
// @Param       access_token    header  string  true    "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/mep_capabilities/:capabilityId [get]
func (c *LcmController) QueryMepCapabilities() {
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	err = util.ValidateAccessToken(accessToken,
		[]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole}, tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}

	util.ClearByteArray(bKey)

	_, err = c.getUrlHostIP(clientIp)
	if err != nil {
		return
	}

	mepPort := util.GetMepPort()

	capabilityId, err := c.getUrlCapabilityId(clientIp)
	if err != nil {
		return
	}

	uri := util.CapabilityUri
	if len(capabilityId) != 0 {
		uri = util.CapabilityUri + "/" + capabilityId
	}

	mepCapabilities, statusCode, err := util.GetHostInfo("mep-mm5.mep" + ":" + mepPort + uri)
	if err != nil {
		c.handleLoggingForError(clientIp, statusCode, "invalid mepCapabilities query")
		return
	}

	_, err = c.Ctx.ResponseWriter.Write([]byte(mepCapabilities))
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	c.handleLoggingForSuccess(clientIp, "Query mep capabilities is successful")
}

// Write error response
func (c *LcmController) writeErrorResponse(errMsg string, code int) {
	log.Error(errMsg)
	c.writeResponse(errMsg, code)
}

// Write response
func (c *LcmController) writeResponse(msg string, code int) {
	c.Data["json"] = msg
	c.Ctx.ResponseWriter.WriteHeader(code)
	c.ServeJSON()
}

// Get csar file
func (c *LcmController) getFile(clientIp string) (multipart.File, *multipart.FileHeader, error) {
	file, header, err := c.GetFile("file")
	if err != nil || file == nil {
		c.handleLoggingForError(clientIp, util.BadRequest, "Failed to get csar file")
		return nil, nil, err
	}

	defer file.Close()
	return file, header, nil
}

// Gets deployment artifact
func (c *LcmController) getDeploymentArtifact(dir string, ext string) (string, error) {
	d, err := os.Open(dir)
	if err != nil {
		log.Info("failed to open the directory")
		return "", err
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		log.Info("failed to read the directory")
		return "", err
	}

	for _, file := range files {
		if file.Mode().IsRegular() && (filepath.Ext(file.Name()) == ext ||
			filepath.Ext(file.Name()) == ".gz" || filepath.Ext(file.Name()) == ".tgz") {
			return dir + "/" + file.Name(), nil
		}
	}
	return "", err
}

// Get deployment type from main service template file
func (c *LcmController) getApplicationDeploymentType(mainServiceTemplateMf string) (string, error) {

	var deployType = "helm"

	templateMf, err := ioutil.ReadFile(mainServiceTemplateMf)
	if err != nil {
		c.writeErrorResponse("Failed to read file", util.BadRequest)
		return "", err
	}

	jsondata, err := yaml.YAMLToJSON(templateMf)
	if err != nil {
		c.writeErrorResponse("failed to convert from YAML to JSON", util.BadRequest)
		return "", err
	}

	var mainService map[string]interface{}
	err = json.Unmarshal(jsondata, &mainService)
	if err != nil {
		c.writeErrorResponse("failed to unmarshal json data", util.StatusInternalServerError)
		return "", err
	}

	for key, value := range mainService {
		if key == "non_mano_artifact_sets" {
			manoArtifact := value.(map[string]interface{})
			for key1 := range manoArtifact {
				if key1 == "applcm_helm_chart_deployment" {
					deployType = "helm"
				} else if key1 == "applcm_k8s_chart_deployment" {
					deployType = "kubernetes"
				} else if key1 == "applcm_VM_chart_deployment" {
					deployType = "vm"
				}
			}
		}
	}

	return deployType, nil
}

// Opens package
func (c *LcmController) openPackage(packagePath string) string {
	zipReader, _ := zip.OpenReader(packagePath)
	if len(zipReader.File) > util.TooManyFile {
		c.writeErrorResponse("Too many files contains in zip file", util.StatusInternalServerError)
	}
	var totalWrote int64
	dirName := util.RandomDirectoryName(10)
	err := os.MkdirAll(PackageFolderPath+dirName, 0750)
	if err != nil {
		c.writeErrorResponse("Failed to make directory", util.StatusInternalServerError)
		return err.Error()
	}
	for _, file := range zipReader.Reader.File {

		zippedFile, err := file.Open()
		if err != nil || zippedFile == nil {
			c.writeErrorResponse("Failed to open zip file", util.StatusInternalServerError)
			continue
		}
		if file.UncompressedSize64 > util.SingleFileTooBig || totalWrote > util.TooBig {
			c.writeErrorResponse("File size limit is exceeded", util.StatusInternalServerError)
		}

		defer zippedFile.Close()

		isContinue, wrote := c.extractFiles(file, zippedFile, totalWrote, dirName)
		if isContinue {
			continue
		}
		totalWrote = wrote
	}

	return dirName
}

// Extract files
func (c *LcmController) extractFiles(file *zip.File, zippedFile io.ReadCloser, totalWrote int64, dirName string) (bool, int64) {
	targetDir := PackageFolderPath + dirName
	extractedFilePath := filepath.Join(
		targetDir,
		file.Name,
	)

	if file.FileInfo().IsDir() {
		err := os.MkdirAll(extractedFilePath, 0750)
		if err != nil {
			c.writeErrorResponse("Failed to make directory", util.StatusInternalServerError)
		}
	} else {
		outputFile, err := os.OpenFile(
			extractedFilePath,
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
			0750,
		)
		if err != nil || outputFile == nil {
			c.writeErrorResponse("The output file is nil", util.StatusInternalServerError)
			return true, totalWrote
		}

		defer outputFile.Close()

		wt, err := io.Copy(outputFile, zippedFile)
		if err != nil {
			c.writeErrorResponse("Failed to copy zipped file", util.StatusInternalServerError)
		}
		totalWrote += wt
	}
	return false, totalWrote
}

// Instantiate application
func (c *LcmController) InstantiateApplication(pluginInfo string, hostIp string,
	artifact string, clientIp string, accessToken string, akSkAppInfo config.AppAuthConfig) error {
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return err
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	err, _ = adapter.Instantiate(hostIp, artifact, accessToken, akSkAppInfo)
	if err != nil {
		errorString := err.Error()
		if strings.Contains(errorString, util.Forbidden) {
			c.handleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
		} else if strings.Contains(errorString, util.AccessTokenIsInvalid) {
			c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		} else {
			c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		}
		return err
	}
	return nil
}

// Get app info record
func (c *LcmController) getAppInfoRecord(appInsId string, clientIp string) (*models.AppInfoRecord, error) {
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

// Get app name
func (c *LcmController) getAppName(clientIp string) (string, error) {
	appName := c.GetString("appName")
	name, err := util.ValidateName(appName)
	if err != nil || !name {
		c.handleLoggingForError(clientIp, util.BadRequest, "AppName is invalid")
		return "", errors.New("AppName is invalid")
	}
	return appName, nil
}

// Get host IP
func (c *LcmController) getHostIP(clientIp string) (string, error) {
	hostIp := c.GetString("hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, "HostIp address is invalid")
		return "", err
	}
	return hostIp, nil
}

// Get Package Id
func (c *LcmController) getPackageId(clientIp string) (string, error) {
	packageId := c.GetString("packageId")
	if packageId != "" {
		uuid, err := util.IsValidUUID(packageId)
		if err != nil || !uuid {
			c.handleLoggingForError(clientIp, util.BadRequest, "package id is invalid")
			return "", err
		}
		return packageId, nil
	}
	return "", nil
}

// Get Package Id from url
func (c *LcmController) getUrlPackageId(clientIp string) (string, error) {
	packageId := c.GetString(":packageId")
	if packageId != "" {
		uuid, err := util.IsValidUUID(packageId)
		if err != nil || !uuid {
			c.handleLoggingForError(clientIp, util.BadRequest, "package id is invalid")
			return "", errors.New("invalid package id")
		}
		return packageId, nil
	}
	return "", nil
}

// Get host IP from url
func (c *LcmController) getUrlHostIP(clientIp string) (string, error) {
	hostIp := c.Ctx.Input.Param(":hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, "HostIp address is invalid from url")
		return "", err
	}
	return hostIp, nil
}

// Get mep capability id from url
func (c *LcmController) getUrlCapabilityId(clientIp string) (string, error) {
	capabilityId := c.Ctx.Input.Param(":capabilityId")
	err := util.ValidateMepCapabilityId(capabilityId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, "capability id is invalid from url")
		return "", err
	}
	return capabilityId, nil
}

// Get app Instance Id
func (c *LcmController) getAppInstId(clientIp string) (string, error) {
	appInsId := c.Ctx.Input.Param(":appInstanceId")
	err := util.ValidateUUID(appInsId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, "App instance is invalid")
		return "", err
	}
	return appInsId, nil
}

// Get app Instance Id
func (c *LcmController) getTenantId(clientIp string) (string, error) {
	tenantId := c.Ctx.Input.Param(":tenantId")
	err := util.ValidateUUID(tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, "Tenant id is invalid")
		return "", err
	}
	return tenantId, nil
}

// Get app Instance Id
func (c *LcmController) isTenantAvailable() bool {
	tenantId := c.Ctx.Input.Param(":tenantId")
	return tenantId != ""
}

// Create package path
func (c *LcmController) createPackagePath(pkgPath string, clientIp string, file multipart.File) error {

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Failed to copy csar file")
		return err
	}

	newFile, err := os.Create(pkgPath)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Failed to create package path")
		return err
	}
	defer newFile.Close()
	if _, err := newFile.Write(buf.Bytes()); err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Failed to write csar file")
		return err
	}
	return nil
}

// Get artifact and plugin info
func (c *LcmController) getArtifactAndPluginInfo(deployType string, packageName string,
	clientIp string, vim string) (string, string, error) {
	switch deployType {
	case "helm":
		pkgPath := PackageFolderPath + packageName + PackageArtifactPath + "Charts"
		artifact, err := c.getDeploymentArtifact(pkgPath, ".tar")
		if artifact == "" {
			c.handleLoggingForError(clientIp, util.StatusInternalServerError,
				"Artifact not available in application package.")
			return "", "", err
		}

		pluginInfo := util.GetPluginInfo(vim)
		return artifact, pluginInfo, nil
	default:
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.DeployTypeIsNotHelmBased)
		return "", "", errors.New("deployment type is not helm based")
	}
}

// Handled logging for error case
func (c *LcmController) handleLoggingForError(clientIp string, code int, errMsg string) {
	c.writeErrorResponse(errMsg, code)
	log.Info("Response message for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
}

// Insert or update application info record
func (c *LcmController) insertOrUpdateAppInfoRecord(appInsId, hostIp, deployType, clientIp, tenantId, packageId string) error {
	appInfoRecord := &models.AppInfoRecord{
		AppInsId:   appInsId,
		HostIp:     hostIp,
		DeployType: deployType,
		TenantId:   tenantId,
		PackageId:  packageId,
	}

	count, err := c.Db.QueryCountForAppInfo("app_info_record", util.TenantId, tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	if count >= util.MaxNumberOfRecords {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"Maximum number of app info records are exceeded for given tenant")
		return errors.New("maximum number of app info records are exceeded for given tenant")
	}

	err = c.Db.InsertOrUpdateData(appInfoRecord, util.AppInsId)
	if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
		log.Error("Failed to save app info record to database.")
		return err
	}
	return nil
}

// Insert or update tenant info record
func (c *LcmController) insertOrUpdateTenantRecord(clientIp, tenantId string) error {
	tenantRecord := &models.TenantInfoRecord{
		TenantId: tenantId,
	}

	count, err := c.Db.QueryCount("tenant_info_record")
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	if count >= util.MaxNumberOfTenantRecords {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"Maximum number of tenant records are exceeded")
		return errors.New("maximum number of tenant records are exceeded")
	}

	err = c.Db.InsertOrUpdateData(tenantRecord, util.TenantId)
	if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
		log.Error("Failed to save tenant record to database.")
		return err
	}
	return nil
}

// Delete app info record
func (c *LcmController) deleteAppInfoRecord(appInsId string) error {
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
func (c *LcmController) deleteTenantRecord(clientIp, tenantId string) error {
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

// Get input parameters
func (c *LcmController) getInputParameters(clientIp string) (string, string, multipart.File,
	*multipart.FileHeader, string, string, error) {
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		return "", "", nil, nil, "", "", err
	}

	appInsId, err := c.getAppInstId(clientIp)
	if err != nil {
		return "", "", nil, nil, "", "", err
	}

	file, header, err := c.getFile(clientIp)
	if err != nil {
		return "", "", nil, nil, "", "", err
	}
	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		return "", "", nil, nil, "", "", err
	}

	packageId, err := c.getPackageId(clientIp)
	if err != nil {
		return "", "", nil, nil, "", "", err
	}

	return hostIp, appInsId, file, header, tenantId, packageId, nil
}

// To display log for received message
func (c *LcmController) displayReceivedMsg(clientIp string) {
	log.Info("Received message from ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "]")
}

// Returns the utilization details
func (c *LcmController) metricValue(statInfo models.KpiModel) (metricResponse map[string]interface{}, err error) {
	clientIp := c.Ctx.Input.IP()
	err = util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return metricResponse, err
	}
	c.displayReceivedMsg(clientIp)

	if len(statInfo.Data.Result) == 0 {
		metricResponse = map[string]interface{}{
			"total": "0.0",
			"used":  "0.0",
		}
	} else if len(statInfo.Data.Result[0].Value) > 2 {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.UnexpectedValue)
		return metricResponse, errors.New(util.UnexpectedValue)
	} else {
		metricResponse = map[string]interface{}{
			"total": statInfo.Data.Result[0].Value[0],
			"used":  statInfo.Data.Result[0].Value[1],
		}
	}
	return metricResponse, nil
}

func (c *LcmController) getCpuUsage(prometheusServiceName, prometheusPort, clientIp string) (cpuUtilization map[string]interface{}, err error) {
	var statInfo models.KpiModel

	cpu, statusCode, errCpu := util.GetHostInfo(prometheusServiceName + ":" + prometheusPort + util.CpuQuery)
	if errCpu != nil {
		c.handleLoggingForError(clientIp, statusCode, "invalid cpu query")
		return cpuUtilization, errCpu
	}
	err = json.Unmarshal([]byte(cpu), &statInfo)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.UnMarshalError)
		return cpuUtilization, err
	}
	cpuUtilization, err = c.metricValue(statInfo)
	if err != nil {
		return cpuUtilization, err
	}
	return cpuUtilization, nil
}

func (c *LcmController) getMemoryUsage(prometheusServiceName, prometheusPort, clientIp string) (memUsage map[string]interface{}, err error) {
	var statInfo models.KpiModel

	mem, statusCode, err := util.GetHostInfo(prometheusServiceName + ":" + prometheusPort + util.MemQuery)
	if err != nil {
		c.handleLoggingForError(clientIp, statusCode, "invalid memory query")
		return memUsage, err
	}
	err = json.Unmarshal([]byte(mem), &statInfo)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.UnMarshalError)
		return memUsage, err
	}
	memUsage, err = c.metricValue(statInfo)
	if err != nil {
		return memUsage, err
	}
	return memUsage, nil
}

func (c *LcmController) diskUsage(prometheusServiceName string, prometheusPort, clientIp string) (diskUtilization map[string]interface{}, err error) {
	var statInfo models.KpiModel

	disk, statusCode, err := util.GetHostInfo(prometheusServiceName + ":" + prometheusPort + util.DiskQuery)
	if err != nil {
		c.handleLoggingForError(clientIp, statusCode, "invalid disk query")
		return diskUtilization, err
	}
	err = json.Unmarshal([]byte(disk), &statInfo)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.UnMarshalError)
		return diskUtilization, err
	}
	diskUtilization, err = c.metricValue(statInfo)
	if err != nil {
		return diskUtilization, err
	}
	return diskUtilization, nil
}

func (c *LcmController) handleLoggingK8s(clientIp string, errorString string) {
	if strings.Contains(errorString, util.Forbidden) {
		c.handleLoggingForError(clientIp, util.StatusForbidden, util.Forbidden)
	} else if strings.Contains(errorString, util.AccessTokenIsInvalid) {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
	} else {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, errorString)
	}
}

func (c *LcmController) getPluginAdapter(deployType, clientIp string, vim string) (*pluginAdapter.PluginAdapter, error) {
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

func (c *LcmController) handleErrorForInstantiateApp(acm config.AppConfigAdapter,
	clientIp, appInsId, tenantId string) {
	err := acm.DeleteAppAuthConfig()
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}
	err = c.deleteAppInfoRecord(appInsId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}

	err = c.deleteTenantRecord(clientIp, tenantId)
	if err != nil {
		return
	}
}

func (c *LcmController) getPkgName(clientIp string, bKey []byte,
	header *multipart.FileHeader, file multipart.File) (string, string, string, error) {
	var fileName = ""

	pkgPath := PackageFolderPath + header.Filename
	err := c.createPackagePath(pkgPath, clientIp, file)
	if err != nil {
		util.ClearByteArray(bKey)
		return "", "", "", err
	}

	packageName := c.openPackage(pkgPath)
	files, err := getFilesFromDir(packageName)
	if err != nil {
		util.ClearByteArray(bKey)
		c.removeCsarFiles(packageName, header, clientIp)
		return "", "", "", err
	}

	path := packageName
	if len(files) == 1 {
		path = packageName + "/" + files[0].Name()
		files, err = getFilesFromDir(packageName + "/" + files[0].Name())
		if err != nil {
			util.ClearByteArray(bKey)
			c.removeCsarFiles(packageName, header, clientIp)
			return "", "", "", err
		}
	}
	fileName = getManifestFileName(files)
	return packageName, path, fileName, nil
}

// Get manifest file name
func getManifestFileName(files []os.FileInfo) string {
	var fileName = ""

	for _, file := range files {
		if file.IsDir() {
			continue
		} else {
			fileName = file.Name()
			break
		}
	}
	return fileName
}

// Get files from directory
func getFilesFromDir(packageName string) (files []os.FileInfo, err error) {
	f, err := os.Open(PackageFolderPath + packageName)
	if err != nil {
		return files, err
	}
	files, err = f.Readdir(-1)
	f.Close()
	if err != nil {
		return files, err
	}
	return files, nil
}

// Handled logging for success case
func (c *LcmController) handleLoggingForSuccess(clientIp string, msg string) {
	log.Info("Response message for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Success: " + msg + ".]")
}

// @Title GetPodDescription
// @Description perform get pod description
// @Param	tenantId	    path 	string	true	"tenantId"
// @Param	appInstanceId   path 	string	true	"appInstanceId"
// @Param   access_token    header  string  true    "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/:appInstanceId/pods/desc  [get]
func (c *LcmController) GetPodDescription() {
	log.Info("Get pod description request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	err = util.ValidateAccessToken(accessToken,
		[]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole}, tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}

	appInsId, err := c.getAppInstId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appInfoRecord, err := c.getAppInfoRecord(appInsId, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	vim, err := c.getVim(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.getPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	response, err := adapter.GetPodDescription(accessToken, appInfoRecord.HostIp, appInsId)
	util.ClearByteArray(bKey)
	if err != nil {
		res := strings.Contains(err.Error(), "not found")
		if res {
			c.handleLoggingForError(clientIp, util.StatusNotFound, err.Error())
			return
		}
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	c.handleLoggingForSuccess(clientIp, "Pod description is successful")
}

// Get vim name
func (c *LcmController) getVim(clientIp string) (string, error) {

	// Get VIM from host table, TBD
	vim := ""

	// Default to k8s for backward compatibility
	if vim == "" {
		log.Info("Setting plugin to default value which is k8s, as no VIM is mentioned explicitly")
		vim = "k8s"
	}
	return vim, nil
}


