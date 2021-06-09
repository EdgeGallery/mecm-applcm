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
	"mime/multipart"
	"path"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ghodss/yaml"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"os"

	log "github.com/sirupsen/logrus"
)

var (
	PackageFolderPath   = "/usr/app/packages/"
)

// Lcm Controller
type LcmController struct {
	BaseController
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
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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
	hostIp, vim, file, err := c.getInputParametersForUploadCfg(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	hostInfoRec := &models.MecHost{
		MecHostId: hostIp,
	}

	readErr := c.Db.ReadData(hostInfoRec, util.HostIp)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			util.MecHostRecDoesNotExist)
		return
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return
	}

	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.UploadConfig(file, hostIp, accessToken)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleLoggingForFailure(clientIp, err.Error())
		return
	}

	hostInfoRec.ConfigUploadStatus = "Uploaded"
	err = c.Db.InsertOrUpdateData(hostInfoRec, util.HostIp)
	if err != nil && err.Error() != util.LastInsertIdNotSupported {
		log.Error("Failed to save mec host info record to database.")
		return
	}
	c.handleLoggingForSuccess(clientIp, "Upload config is successful")
	c.ServeJSON()
}

// Validate kubeconfig file
func (c *LcmController) validateYamlFile(clientIp string, file multipart.File) error {

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Failed to copy file into buffer")
		return err
	}

	_, err := yaml.YAMLToJSON(buf.Bytes())
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "KubeConfig file validation is failed")
		return err
	}
	return nil
}

// extract CSAR package
func extractCsarPackage(packagePath string) (string, error) {
	zipReader, _ := zip.OpenReader(packagePath)
	if len(zipReader.File) > util.TooManyFile {
		return "", errors.New("Too many files contains in zip file")
	}
	var totalWrote int64
	packageDir := path.Dir(packagePath)
	err := os.MkdirAll(packageDir, 0750)
	if err != nil {
		log.Error(util.FailedToMakeDir)
		return "" ,errors.New(util.FailedToMakeDir)
	}
	for _, file := range zipReader.Reader.File {

		zippedFile, err := file.Open()
		if err != nil || zippedFile == nil {
			log.Error("Failed to open zip file")
			continue
		}
		if file.UncompressedSize64 > util.SingleFileTooBig || totalWrote > util.TooBig {
			log.Error("File size limit is exceeded")
		}

		defer zippedFile.Close()

		isContinue, wrote := extractFiles(file, zippedFile, totalWrote, packageDir)
		if isContinue {
			continue
		}
		totalWrote = wrote
	}
	return packageDir, nil
}

// Extract files
func extractFiles(file *zip.File, zippedFile io.ReadCloser, totalWrote int64, dirName string) (bool, int64) {
	targetDir := dirName
	extractedFilePath := filepath.Join(
		targetDir,
		file.Name,
	)

	if file.FileInfo().IsDir() {
		err := os.MkdirAll(extractedFilePath, 0750)
		if err != nil {
			log.Error("Failed to create directory")
		}
	} else {
		outputFile, err := os.OpenFile(
			extractedFilePath,
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
			0750,
		)
		if err != nil || outputFile == nil {
			log.Error("The output file is nil")
			return true, totalWrote
		}

		defer outputFile.Close()

		wt, err := io.Copy(outputFile, zippedFile)
		if err != nil {
			log.Error("Failed to copy zipped file")
		}
		totalWrote += wt
	}
	return false, totalWrote
}

// get file with extension
func (c *LcmController) getFileContainsExtension(clientIp string, pkgDir string, ext string) (string, error) {
	d, err := os.Open(pkgDir)
	if err != nil {
        log.Error("failed to find application package")
		return "", errors.New("failed to find  application package")
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		log.Error("failed to read application package")
		return "", errors.New("failed to read application package")
	}

	for _, file := range files {
		if file.Mode().IsRegular() && filepath.Ext(file.Name()) == ext {
			return pkgDir + "/" + file.Name(), nil
		}
	}
	log.Error(util.FileNameNotFound + ext)
	return "", errors.New(util.FileNameNotFound + ext)
}

// Get application package details
func (c *LcmController) getPackageDetailsFromPackage(clientIp string,
	packageDir string) (models.AppPkgDetails, error) {

	var pkgDetails models.AppPkgDetails
	mf, err := c.getFileContainsExtension(clientIp, packageDir, ".mf")
    if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return pkgDetails, errors.New("failed to find mf file")
	}

	mfYaml, err := os.Open(mf)
	if err != nil {
		log.Error("failed to read mf file")
		return pkgDetails, errors.New("failed to read mf file")
	}
	defer mfYaml.Close()

	mfFileBytes, _ := ioutil.ReadAll(mfYaml)

	data, err := yaml.YAMLToJSON(mfFileBytes)
	if err != nil {
		log.Error("failed to convert yaml to json")
		return pkgDetails, errors.New("failed to convert yaml to json")
	}

	err = json.Unmarshal(data, &pkgDetails)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.UnMarshalError)
		return pkgDetails, err
	}
	return pkgDetails, nil
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
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, "")
	if err != nil {
		c.HandleLoggingForTokenFailure(clientIp, err.Error())
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	hostIp, vim, hostInfoRec, err := c.getInputParametersForRemoveCfg(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.RemoveConfig(hostIp, accessToken)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleLoggingForFailure(clientIp, err.Error())
		return
	}
	hostInfoRec.ConfigUploadStatus = ""
	err = c.Db.InsertOrUpdateData(hostInfoRec, util.HostIp)
	if err != nil && err.Error() != util.LastInsertIdNotSupported {
		log.Error("Failed to save mec host info record to database.")
		return
	}
	c.handleLoggingForSuccess(clientIp, "Remove config is successful")
	c.ServeJSON()
}

// @Title Instantiate application
// @Description Instantiate application
// @Param   hostIp          body 	string	true   "hostIp"
// @Param   appName         body 	string	true   "appName"
// @Param   packageId       body 	string	true   "packageId"
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
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)

	var req models.InstantiateRequest
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &req)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		return
	}
	if req.Parameters == nil {
		req.Parameters = make(map[string]string)
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	appInsId, tenantId, hostIp, packageId, appName, err := c.validateToken(accessToken, req, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	originVar, err := util.ValidateName(req.Origin, util.NameRegex)
	if err != nil || !originVar {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.BadRequest, util.OriginIsInvalid)
		return
	}

	appPkgHostRecord := &models.AppPackageHostRecord{
		PkgHostKey: packageId + tenantId + hostIp,
	}

	readErr := c.Db.ReadData(appPkgHostRecord, util.PkgHostKey)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			"App package host record not exists")
		util.ClearByteArray(bKey)
		return
	}
	if appPkgHostRecord.Status != "Distributed" {
		c.HandleLoggingForError(clientIp, util.BadRequest,
			"application package distribution status is:" + appPkgHostRecord.Status)
		util.ClearByteArray(bKey)
		return
	}

	appInfoRecord := &models.AppInfoRecord{
		AppInstanceId: appInsId,
	}

	readErr = c.Db.ReadData(appInfoRecord, util.AppInsId)
	if readErr == nil {
		c.HandleLoggingForError(clientIp, util.BadRequest,
			"App instance info record already exists")
		util.ClearByteArray(bKey)
		return
	}

	vim, err := c.getVim(clientIp, hostIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return
	}

	err, acm := processAkSkConfig(appInsId, appName, &req, clientIp, tenantId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		util.ClearByteArray(bKey)
		return
	}

	err = c.insertOrUpdateTenantRecord(clientIp, tenantId)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	var appInfoParams models.AppInfoRecord
	appInfoParams.AppInstanceId = appInsId
	appInfoParams.MecHost = hostIp

	appInfoParams.TenantId = tenantId
	appInfoParams.AppPackageId = packageId
	appInfoParams.AppName = appName
	appInfoParams.Origin = req.Origin

	err = c.insertOrUpdateAppInfoRecord(clientIp, appInfoParams)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	err, status := adapter.Instantiate(tenantId, accessToken, appInsId, req)
	util.ClearByteArray(bKey)
	if err != nil {
		c.handleErrorForInstantiateApp(acm, clientIp, appInsId, tenantId)
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}
	if status == util.Failure {
		c.handleErrorForInstantiateApp(acm, clientIp, appInsId, tenantId)
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToUploadToPlugin)
		err = errors.New("failed to instantiate app")
		return
	}

	c.handleLoggingForSuccess(clientIp, "Application instantiated successfully")
	c.ServeJSON()
}

func (c *LcmController) validateToken(accessToken string, req models.InstantiateRequest,  clientIp string) (string, string, string, string, string, error) {

	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.RequestBodyTooLarge)
		return "", "", "", "", "", errors.New(util.RequestBodyTooLarge)
	}

	appInsId, tenantId, hostIp, packageId, appName, err := c.ValidateInstantiateInputParameters(clientIp, req)
	if err != nil {
		return "", "", "", "", "", err
	}
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, tenantId)
	if err != nil {
		c.HandleLoggingForTokenFailure(clientIp, err.Error())
		return "", "", "", "", "", err
	}
	return appInsId, tenantId, hostIp, packageId, appName, nil
}

// Process Ak Sk configuration
func processAkSkConfig(appInsId, appName string, req *models.InstantiateRequest, clientIp string,
	tenantId string) (error, config.AppConfigAdapter) {
	var applicationConfig config.ApplicationConfig

	appAuthConfig := config.NewAppAuthCfg(appInsId)
	if req.Parameters["ak"] == "" || req.Parameters["sk"] == "" {
		err := appAuthConfig.GenerateAkSK()
		if err != nil {
			return err, config.AppConfigAdapter{}
		}
		req.Parameters["ak"] = appAuthConfig.Ak
		req.Parameters["sk"] = appAuthConfig.Sk
		req.AkSkLcmGen = true
	} else {
		appAuthConfig.Ak = req.Parameters["ak"]
		appAuthConfig.Sk = req.Parameters["sk"]
		req.AkSkLcmGen = false
	}

	appConfigFile, err := getApplicationConfigFile(tenantId, req.PackageId)
	if err != nil {
		log.Error("failed to get application configuration file")
		return err, config.AppConfigAdapter{}
	}

	configYaml, err := os.Open(PackageFolderPath + tenantId + "/" + req.PackageId + "/APPD/" + appConfigFile)
	if err != nil {
		log.Error("failed to read config file")
		return err, config.AppConfigAdapter{}
	}
	defer configYaml.Close()

	mfFileBytes, _ := ioutil.ReadAll(configYaml)

	data, err := yaml.YAMLToJSON(mfFileBytes)
	if err != nil {
		log.Error("failed to convert yaml to json")
		return err, config.AppConfigAdapter{}
	}

	err = json.Unmarshal(data, &applicationConfig)
	if err != nil {
		log.Error(util.UnMarshalError)
		return err, config.AppConfigAdapter{}
	}

	acm := config.NewAppConfigMgr(appInsId, appName, appAuthConfig, applicationConfig)
	err = acm.PostAppAuthConfig(clientIp)
	if err != nil {
		return err, config.AppConfigAdapter{}
	}
	return nil, acm
}

// Get application config file
func getApplicationConfigFile(tenantId string, packageId string) (string, error) {
	var zipFile string

	files, err := ioutil.ReadDir(PackageFolderPath + tenantId + "/" + packageId + "/" + "APPD")
	if err != nil {
		log.Error("failed to read directory")
		return "", nil
	}

	for _, filename := range files {
		if filepath.Ext(filename.Name()) == ".zip" {
			zipFile = filename.Name()
			break
		}
	}

	pkgDir, err := extractCsarPackage(PackageFolderPath + tenantId + "/" + packageId + "/" + "APPD" + "/" + zipFile)
	if err != nil {
		log.Error("failed to extract package")
		return "", err
	}

	mfYaml, err := os.Open(pkgDir + "/TOSCA_VNFD.meta")
	if err != nil {
		log.Error("failed to read mf file")
		return "", err
	}
	defer mfYaml.Close()

	mfFileBytes, _ := ioutil.ReadAll(mfYaml)

	data, err := yaml.YAMLToJSON(mfFileBytes)
	if err != nil {
		log.Error("failed to convert yaml to json")
		return "", err
	}
	var vnfData models.VnfData

	err = json.Unmarshal(data, &vnfData)
	if err != nil {
		log.Error(util.UnMarshalError)
		return "", err
	}
	return vnfData.EntryDefinitions, nil
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
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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

	vim, err := c.getVim(clientIp, appInfoRecord.MecHost)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.getPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	_, err = adapter.Terminate(appInfoRecord.MecHost, accessToken, appInfoRecord.AppInstanceId)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleLoggingForFailure(clientIp, err.Error())
		return
	}

	acm := config.NewAppConfigMgr(appInsId, "", config.AppAuthConfig{}, config.ApplicationConfig{})
	err = acm.DeleteAppAuthConfig(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}

	var origin = appInfoRecord.Origin

	err = c.deleteAppInfoRecord(appInsId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}

	err = c.deleteTenantRecord(clientIp, tenantId)
	if err != nil {
		return
	}

	appInsKeyRec := &models.AppInstanceStaleRec{
		AppInstanceId: appInsId,
		TenantId:      tenantId,
	}
	if strings.EqualFold(origin, "mepm") {
		err = c.Db.InsertOrUpdateData(appInsKeyRec, util.AppInsId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			log.Error("Failed to save app instance key record to database.")
			return
		}
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
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken,
		[]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole}, "")
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
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
		MecHost:      hostIp,
		AppPackageId: packageId,
	}

	response := map[string]bool{"package_deployed": true}
	readErr := c.Db.ReadData(appInfoRecord, util.PkgId, "host_ip")
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
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
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
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
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

	vim, err := c.getVim(clientIp, appInfoRecord.MecHost)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.getPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	response, err := adapter.Query(accessToken, appInsId, appInfoRecord.MecHost)
	util.ClearByteArray(bKey)
	if err != nil {
		res := strings.Contains(err.Error(), "not found")
		if res {
			c.HandleLoggingForError(clientIp, util.StatusNotFound, err.Error())
			return
		}
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	c.handleLoggingForSuccess(clientIp, "Query workload statistics is successful")
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
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		util.ClearByteArray(bKey)
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
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.MarshalError)
		return
	}

	_, err = c.Ctx.ResponseWriter.Write(metricInfoByteArray)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
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
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		util.ClearByteArray(bKey)
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
		c.HandleLoggingForError(clientIp, statusCode, "invalid mepCapabilities query")
		return
	}

	_, err = c.Ctx.ResponseWriter.Write([]byte(mepCapabilities))
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	c.handleLoggingForSuccess(clientIp, "Query mep capabilities is successful")
}

// Get host IP
func (c *LcmController) getHostIP(clientIp string) (string, error) {
	hostIp := c.GetString("hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.HostIpIsInvalid)
		return "", err
	}
	return hostIp, nil
}

// Get origin
func (c *LcmController) getOrigin(clientIp string) (string, error) {
	origin := c.GetString("origin")
	originVar, err := util.ValidateName(origin, util.NameRegex)
	if err != nil || !originVar {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Origin is invalid")
		return "", errors.New(util.OriginIsInvalid)
	}
	return origin, nil
}

// Get host IP
func (c *LcmController) getUrlHostIP(clientIp string) (string, error) {
	hostIp := c.Ctx.Input.Param(":hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.HostIpIsInvalid)
		return "", err
	}
	return hostIp, nil
}

// Get Package Id
func (c *LcmController) getPackageId(clientIp string) (string, error) {
	packageId := c.GetString("packageId")
	if packageId != "" {
		if len(packageId) > 64 {
			c.HandleLoggingForError(clientIp, util.BadRequest, util.PackageIdIsInvalid)
			return "", errors.New("package id length exceeds max limit")
		}
		return packageId, nil
	}
	return "", nil
}

// Get app Id
func (c *LcmController) getAppId(clientIp string) (string, error) {
	appId := c.GetString("appId")
	if appId != "" {
		if len(appId) > 32 {
			c.HandleLoggingForError(clientIp, util.BadRequest, "app id is invalid")
			return "", errors.New("app id length exceeds max limit")
		}
		return appId, nil
	}
	return "", nil
}
// Get Package Id from url
func (c *LcmController) getUrlPackageId(clientIp string) (string, error) {
	packageId := c.Ctx.Input.Param(":packageId")
	if packageId != "" {
		//uuid, err := util.IsValidUUID(packageId)
		if len(packageId) > 64 {
			c.HandleLoggingForError(clientIp, util.BadRequest, util.PackageIdIsInvalid)
			return "", errors.New("invalid package id")
		}
		return packageId, nil
	}
	return "", nil
}

// Get mep capability id from url
func (c *LcmController) getUrlCapabilityId(clientIp string) (string, error) {
	capabilityId := c.Ctx.Input.Param(":capabilityId")
	err := util.ValidateMepCapabilityId(capabilityId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "capability id is invalid from url")
		return "", err
	}
	return capabilityId, nil
}

// Create package path
func (c *LcmController) createPackagePath(pkgPath string, clientIp string, file multipart.File) error {

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, "Failed to copy csar file")
		return err
	}

	newFile, err := os.Create(pkgPath)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, "Failed to create package path")
		return err
	}
	defer newFile.Close()
	if _, err := newFile.Write(buf.Bytes()); err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, "Failed to write csar file")
		return err
	}
	return nil
}

// Insert or update application info record
func (c *LcmController) insertOrUpdateAppInfoRecord(clientIp string, appInfoParams models.AppInfoRecord) error {
	origin := appInfoParams.Origin
	if origin == "" {
		origin = "MEO"
	}
	hostInfoRec := &models.MecHost{
		MecHostId: appInfoParams.MecHost,
	}

	readErr := c.Db.ReadData(hostInfoRec, util.HostIp)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			"Mec host info record does not exist in database")
		return readErr
	}
	syncStatus := true
	if origin == "MEPM" {
		syncStatus = false
	}
	appInfoRecord := &models.AppInfoRecord{
		AppInstanceId: appInfoParams.AppInstanceId,
		MecHost:       appInfoParams.MecHost,

		TenantId:     appInfoParams.TenantId,
		AppPackageId: appInfoParams.AppPackageId,
		AppName:      appInfoParams.AppName,
		Origin:       origin,
		SyncStatus:   syncStatus,
		MecHostRec:      hostInfoRec,
	}

	count, err := c.Db.QueryCountForTable("app_info_record", util.TenantId, appInfoParams.TenantId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	if count >= util.MaxNumberOfRecords {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError,
			"Maximum number of app info records are exceeded for given tenant")
		return errors.New("maximum number of app info records are exceeded for given tenant")
	}

	err = c.Db.InsertOrUpdateData(appInfoRecord, util.AppInsId)
	if err != nil && err.Error() != util.LastInsertIdNotSupported {
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
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	if count >= util.MaxNumberOfTenantRecords {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError,
			"Maximum number of tenant records are exceeded")
		return errors.New("maximum number of tenant records are exceeded")
	}

	err = c.Db.InsertOrUpdateData(tenantRecord, util.TenantId)
	if err != nil && err.Error() != util.LastInsertIdNotSupported {
		log.Error("Failed to save tenant record to database.")
		return err
	}
	return nil
}

// Returns the utilization details
func (c *LcmController) metricValue(statInfo models.KpiModel) (metricResponse map[string]interface{}, err error) {
	clientIp := c.Ctx.Input.IP()
	err = util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return metricResponse, err
	}
	c.displayReceivedMsg(clientIp)

	if len(statInfo.Data.Result) == 0 {
		metricResponse = map[string]interface{}{
			"total": "0.0",
			"used":  "0.0",
		}
	} else if len(statInfo.Data.Result[0].Value) > 2 {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.UnexpectedValue)
		return metricResponse, errors.New(util.UnexpectedValue)
	} else {
		metricResponse = map[string]interface{}{
			"total": statInfo.Data.Result[0].Value[0],
			"used":  statInfo.Data.Result[0].Value[1],
		}
	}
	return metricResponse, nil
}

func (c *LcmController) getCpuUsage(prometheusServiceName, prometheusPort,
	clientIp string) (cpuUtilization map[string]interface{}, err error) {
	var statInfo models.KpiModel

	cpu, statusCode, errCpu := util.GetHostInfo(prometheusServiceName + ":" + prometheusPort + util.CpuQuery)
	if errCpu != nil {
		c.HandleLoggingForError(clientIp, statusCode, "invalid cpu query")
		return cpuUtilization, errCpu
	}
	err = json.Unmarshal([]byte(cpu), &statInfo)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.UnMarshalError)
		return cpuUtilization, err
	}
	cpuUtilization, err = c.metricValue(statInfo)
	if err != nil {
		return cpuUtilization, err
	}
	return cpuUtilization, nil
}

func (c *LcmController) getMemoryUsage(prometheusServiceName, prometheusPort,
	clientIp string) (memUsage map[string]interface{}, err error) {
	var statInfo models.KpiModel

	mem, statusCode, err := util.GetHostInfo(prometheusServiceName + ":" + prometheusPort + util.MemQuery)
	if err != nil {
		c.HandleLoggingForError(clientIp, statusCode, "invalid memory query")
		return memUsage, err
	}
	err = json.Unmarshal([]byte(mem), &statInfo)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.UnMarshalError)
		return memUsage, err
	}
	memUsage, err = c.metricValue(statInfo)
	if err != nil {
		return memUsage, err
	}
	return memUsage, nil
}

func (c *LcmController) diskUsage(prometheusServiceName string, prometheusPort,
	clientIp string) (diskUtilization map[string]interface{}, err error) {
	var statInfo models.KpiModel

	disk, statusCode, err := util.GetHostInfo(prometheusServiceName + ":" + prometheusPort + util.DiskQuery)
	if err != nil {
		c.HandleLoggingForError(clientIp, statusCode, "invalid disk query")
		return diskUtilization, err
	}
	err = json.Unmarshal([]byte(disk), &statInfo)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.UnMarshalError)
		return diskUtilization, err
	}
	diskUtilization, err = c.metricValue(statInfo)
	if err != nil {
		return diskUtilization, err
	}
	return diskUtilization, nil
}

func (c *LcmController) handleErrorForInstantiateApp(acm config.AppConfigAdapter,
	clientIp, appInsId, tenantId string) {
	err := acm.DeleteAppAuthConfig(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}
	err = c.deleteAppInfoRecord(appInsId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}

	err = c.deleteTenantRecord(clientIp, tenantId)
	if err != nil {
		return
	}
}


func createDirectory(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return errors.New("failed to create directory")
		}
	}
	return nil
}

func (c *LcmController) saveApplicationPackage(clientIp string, tenantId string, packageId string,
	header *multipart.FileHeader, file multipart.File) (string, error) {

	err := createDirectory(PackageFolderPath + tenantId)
	if err != nil {
		return "", err
	}

	err = createDirectory(PackageFolderPath + tenantId + "/" + packageId)
	if err != nil {
		return "", err
	}

	pkgPath := PackageFolderPath + tenantId + "/" + packageId + "/" + packageId + ".csar"
	err = c.createPackagePath(pkgPath, clientIp, file)
	if err != nil {
		return "", err
	}

	return pkgPath, nil
}


// @Title GetWorkloadDescription
// @Description perform get workload description
// @Param	tenantId	    path 	string	true	"tenantId"
// @Param	appInstanceId   path 	string	true	"appInstanceId"
// @Param   access_token    header  string  true    "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/:appInstanceId/workload/events  [get]
func (c *LcmController) GetWorkloadDescription() {
	log.Info("Get workload description request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
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

	vim, err := c.getVim(clientIp, appInfoRecord.MecHost)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.getPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	response, err := adapter.GetWorkloadDescription(accessToken, appInfoRecord.MecHost, appInsId)
	util.ClearByteArray(bKey)
	if err != nil {
		res := strings.Contains(err.Error(), "not found")
		if res {
			c.HandleLoggingForError(clientIp, util.StatusNotFound, err.Error())
			return
		}
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	c.handleLoggingForSuccess(clientIp, "Workload description is successful")
}

// @Title Sync app instances records
// @Description Sync app instances records
// @Param   tenantId    path 	string	    true   "tenantId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/sync_updated [get]
func (c *LcmController) SynchronizeUpdatedRecord() {
	log.Info("Sync app instances request received.")

	var appInstances []models.AppInfoRecord
	var appInstancesSync []models.AppInfoRecord
	var appInstanceSyncRecords models.AppInfoUpdatedRecords
	var appInstanceRes []models.AppInfoRec

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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

	err = util.ValidateAccessToken(accessToken, []string{util.MecmAdminRole}, tenantId)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}

	_, _ = c.Db.QueryTable("app_info_record", &appInstances, "")
	for _, appInstance := range appInstances {
		if !appInstance.SyncStatus && strings.EqualFold(appInstance.Origin, "mepm") {
			appInstancesSync = append(appInstancesSync, appInstance)
		}
	}

	res, err := json.Marshal(appInstancesSync)
	if err != nil {
		c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
		return
	}
	err = json.Unmarshal(res, &appInstanceRes)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}

	appInstanceSyncRecords.AppInfoUpdatedRecs = append(appInstanceSyncRecords.AppInfoUpdatedRecs, appInstanceRes...)

	res, err = json.Marshal(appInstanceSyncRecords)
	if err != nil {
		c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
		return
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)
	_, err = c.Ctx.ResponseWriter.Write(res)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}

	for _, appInstance := range appInstancesSync {
		appInstance.SyncStatus = true
		err = c.Db.InsertOrUpdateData(&appInstance, util.AppInsId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			log.Error("Failed to save app info record to database.")
			return
		}
	}
	c.handleLoggingForSuccess(clientIp, "AppInstance synchronization is successful")
}

// @Title Sync app instances stale records
// @Description Sync app instances stale records
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/sync_deleted [get]
func (c *LcmController) SynchronizeStaleRecord() {
	log.Info("Sync app instances stale request received.")

	var appInstStaleRecs []models.AppInstanceStaleRec
	var appInstanceStaleRecords models.AppInstanceStaleRecords

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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

	err = util.ValidateAccessToken(accessToken, []string{util.MecmAdminRole}, tenantId)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}
	_, _ = c.Db.QueryTable("app_instance_stale_rec", &appInstStaleRecs, "")

	appInstanceStaleRecords.AppInstanceStaleRecs = append(appInstanceStaleRecords.AppInstanceStaleRecs, appInstStaleRecs...)
	res, err := json.Marshal(appInstanceStaleRecords)
	if err != nil {
		c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
		return
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)
	_, err = c.Ctx.ResponseWriter.Write(res)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	for _, appInstStaleRec := range appInstStaleRecs {
		err = c.Db.DeleteData(&appInstStaleRec, util.AppInsId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
			return
		}
	}
	c.handleLoggingForSuccess(clientIp, "Stale appInstance records synchronization is successful")
}

// Get in put parameters for upload configuration
func (c *LcmController) getInputParametersForUploadCfg(clientIp string) (hostIp string,
	vim string, file multipart.File, err error) {
	hostIp, err = c.getHostIP(clientIp)
	if err != nil {
		return hostIp, vim, file, err
	}

	vim, err = c.getVim(clientIp, hostIp)
	if err != nil {
		return hostIp, vim, file, err
	}

	file, header, err := c.GetFile("configFile")
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Upload config file error")
		return hostIp, vim, file, err
	}

	err = util.ValidateFileExtensionEmpty(header.Filename)
	if err != nil || len(header.Filename) > util.MaxFileNameSize {
		c.HandleLoggingForError(clientIp, util.BadRequest,
			"File shouldn't contains any extension or filename is larger than max size")
		return hostIp, vim, file, err
	}

	err = util.ValidateFileSize(header.Size, util.MaxConfigFile)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "File size is larger than max size")
		return hostIp, vim, file, err
	}

	err = c.validateYamlFile(clientIp, file)
	if err != nil {
		return hostIp, vim, file, err
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		return hostIp, vim, file, err
	}
	return hostIp, vim, file, nil
}

// Get in put parameters for remove configuration
func (c *LcmController) getInputParametersForRemoveCfg(clientIp string) (string, string, *models.MecHost, error) {
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		return "", "", &models.MecHost{}, err
	}

	hostInfoRec := &models.MecHost{
		MecHostId: hostIp,
	}

	readErr := c.Db.ReadData(hostInfoRec, util.HostIp)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			util.MecHostRecDoesNotExist)
		return "", "", hostInfoRec, err
	}

	vim, err := c.getVim(clientIp, hostIp)
	if err != nil {
		return "", "", hostInfoRec, err
	}

	return hostIp, vim, hostInfoRec, err
}

// @Title Upload package
// @Description Upload Package
// @Param   access_token  header     string true   "access token"
// @Param   package       formData   file   true   "package file"
// @Param   appId         header     string true   "app Id"
// @Param   packageId     header     string true   "package ID"
// @Success 200 ok
// @Failure 400 bad request
// @router /packages [post]
func (c *LcmController) UploadPackage() {
	log.Info("Upload application package request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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

	appId, packageId, tenantId, err := c.getInputParametersForUploadPkg(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	origin, err := c.getOrigin(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	file, header, err := c.GetFile("package")
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.BadRequest, "Upload package file error")
		return
	}

	err = util.ValidateFileExtensionCsar(header.Filename)
	if err != nil || len(header.Filename) > util.MaxFileNameSize {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.BadRequest,
			"File shouldn't contains any extension or filename is larger than max size")
		return
	}

	err = util.ValidateFileSize(header.Size, util.MaxAppPackageFile)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.BadRequest, "File size is larger than max size")
		return
	}

	pkgFilePath, err := c.saveApplicationPackage(clientIp, tenantId, packageId, header, file)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return
	}
	pkgDir, err := extractCsarPackage(pkgFilePath)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return
	}

	pkgDetails, err := c.getPackageDetailsFromPackage(clientIp, pkgDir)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.BadRequest, "failed to get app package details")
		return
	}

	err = c.insertOrUpdateTenantRecord(clientIp, tenantId)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	err = c.insertOrUpdateAppPkgRecord(appId, clientIp, tenantId, packageId, pkgDetails, origin)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	c.handleLoggingForSuccess(clientIp, "Uploaded application package successfully")

	appPkgResp, _ := json.Marshal(map[string]string{"appId" : appId,
		                                            "packageId" : packageId})
	_, _ = c.Ctx.ResponseWriter.Write(appPkgResp)
}

func (c *LcmController) ValidateDistributeInputParameters(clientIp string, req models.DistributeRequest) (string, error) {

	for _, hostIp := range req.HostIp {
		err := util.ValidateIpv4Address(hostIp)
		if err != nil {
		    return "", errors.New("invalid host IP")
	    }
	}

	packageId, err := c.getUrlPackageId(clientIp)
	if err != nil {
		return "", errors.New("invalid package ID")
	}
	if len(packageId) == 0 {
		return "", errors.New("invalid package ID length")
	}

	if len(packageId) > 64 {
		return "", errors.New("input parameter length exceeded max limit")
	}

	originVar, err := util.ValidateName(req.Origin, util.NameRegex)
	if err != nil || !originVar {
		return "", errors.New(util.OriginIsInvalid)
	}
	return packageId, nil
}

func (c *LcmController) ValidateInstantiateInputParameters(clientIp string, req models.InstantiateRequest) (string, string, string, string, string, error) {

	hostIp := req.HostIp
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.HostIpIsInvalid)
		return "", "", "",  "", "", err
	}

	packageId := req.PackageId
	if len(packageId) == 0 {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.PackageIdIsInvalid)
		return "", "", "",  "", "", err
	}

	if len(packageId) > 64 {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.PackageIdIsInvalid)
		return "", "", "", "", "", errors.New("package id length exceeds max limit")
	}

	appName := req.AppName
	name, err := util.ValidateName(appName, util.NameRegex)
	if err != nil || !name {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.AppNameIsNotValid)
		return "", "", "",  "", "", errors.New(util.AppNameIsNotValid)
	}

	appInsId, err := c.getAppInstId(clientIp)
	if err != nil {
		return "", "", "",  "", "", err
	}

	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		return "", "", "",  "", "", err
	}

	return appInsId, tenantId, hostIp, packageId, appName, nil
}

// @Title Distribute package
// @Description Distribute Package
// @Param   access_token  header     string true   "access token"
// @Param   packageId     header     string true   "package ID"
// @Param   hostIp        body       string true   "host IP"
// @Success 200 ok
// @Failure 400 bad request
// @router /packages/:packageId [post]
func (c *LcmController) DistributePackage() {
	log.Info("Distribute application package request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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

	var hosts models.DistributeRequest
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &hosts)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		util.ClearByteArray(bKey)
		return
	}

	packageId, err := c.ValidateDistributeInputParameters(clientIp, hosts)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest,
			"invalid input parameters")
		util.ClearByteArray(bKey)
		return
	}

	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appPkgRecord := &models.AppPackageRecord{
		AppPkgId: packageId + tenantId,
	}

	readErr := c.Db.ReadData(appPkgRecord, util.AppPkgId)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			"App package does not exist")
		util.ClearByteArray(bKey)
		return
	}

	err = c.processUploadPackage(hosts, clientIp, tenantId, packageId, accessToken)
	util.ClearByteArray(bKey)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(clientIp, "Distributed application package successfully")
	c.ServeJSON()
}

// @Title Delete application package on host
// @Description Delete Package
// @Param   access_token  header     string true   "access token"
// @Param   packageId     header     string true   "package ID"
// @Param   hostIp        header     string true   "host IP"
// @Success 200 ok
// @Failure 400 bad request
// @router /packages/:packageId/hosts/:hostIp [delete]
func (c *LcmController) DeletePackageOnHost() {
	log.Info("Delete application package on host request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, "")
	if err != nil {
		c.HandleLoggingForTokenFailure(clientIp, err.Error())
		return
	}

	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))

	tenantId, packageId, hostIp, err := c.getInputParametersForDelPkgOnHost(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	pkgRecHostIp, vim, err := c.getVimAndHostIpFromPkgHostRec(clientIp, packageId, tenantId, hostIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.DeletePackage(tenantId, pkgRecHostIp, packageId, accessToken)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleLoggingForFailure(clientIp, err.Error())
		return
	}
	err = c.delAppPkgRecords(clientIp, packageId, tenantId, hostIp)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(clientIp, "Deleted host application package successfully")
	c.ServeJSON()
}

func (c *LcmController) deletePackageFromDir(appPkgPath string) error {

	tenantPath := path.Dir(appPkgPath)

	//remove package directory
	err := os.RemoveAll(appPkgPath)
	if err != nil {
		return errors.New("failed to delete application package file")
	}

	tenantDir, err := os.Open(tenantPath)
	if err != nil {
		return errors.New("failed to delete application package")
	}
	defer tenantDir.Close()

	_, err = tenantDir.Readdir(1)

	if err == io.EOF {
		err := os.Remove(tenantPath)
		if err != nil {
			return errors.New("failed to delete application package")
		}
		return nil
	}
	return nil
}


// @Title Delete package
// @Description Delete package
// @Param	tenantId	path 	string	true   "tenantId"
// @Param	packageId   path 	string	true   "packageId"
// @Param   access_token header  string true   "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/packages/:packageId [delete]
func (c *LcmController) DeletePackage() {
	log.Info("Delete application package request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, "")
	if err != nil {
		c.HandleLoggingForTokenFailure(clientIp, err.Error())
		return
	}
	
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))

	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		return
	}

	packageId, err := c.getUrlPackageId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		return
	}

	err = c.processDeletePackage(clientIp, packageId, tenantId, accessToken)
	util.ClearByteArray(bKey)
	if err != nil {
		return
	}

	pkgFilePath := PackageFolderPath + tenantId + "/" + packageId + "/" + packageId + ".csar"
	err = c.deletePackageFromDir(path.Dir(pkgFilePath))
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}

	err =c.deleteAppPkgRecords(packageId, tenantId, clientIp)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(clientIp, "Deleted application package successfully")
	c.ServeJSON()
}

// Insert or update application package record
func (c *LcmController) insertOrUpdateAppPkgRecord(appId, clientIp, tenantId,
	packageId string, pkgDetails models.AppPkgDetails, origin string) error {

	syncStatus := true
	if origin == "MEPM" {
		syncStatus = false
	}
	appPkgRecord := &models.AppPackageRecord{
		AppPkgId:      packageId + tenantId,
		TenantId:      tenantId,
		PackageId:     packageId,
		AppId:         appId,
		AppPkgName:    pkgDetails.App_product_name,
		AppPkgVersion: pkgDetails.App_package_version,
		AppProvider:   pkgDetails.App_provider_id,
		AppPkgDesc:    pkgDetails.App_package_description,
		CreatedTime:   pkgDetails.App_release_data_time,
		SyncStatus:    syncStatus,
		Origin:        origin,
	}

	count, err := c.Db.QueryCountForTable("app_package_record", util.TenantId, tenantId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	if count >= util.MaxNumberOfRecords {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError,
			"Maximum number of app package records are exceeded for given tenant")
		return errors.New("maximum number of app package records are exceeded for given tenant")
	}
	log.Info("Add app package record: %+v", appPkgRecord)
	err = c.Db.InsertOrUpdateData(appPkgRecord, util.AppPkgId)
	if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
		log.Error("Failed to save app package record to database.")
		return err
	}
	return nil
}

// Insert or update application package host record
func (c *LcmController) insertOrUpdateAppPkgHostRecord(hostIp, clientIp, tenantId,
	packageId, distributionStatus, origin string) error {

	if origin == "" {
		origin = "MECM"
	}

	originVar, err := util.ValidateName(origin, util.NameRegex)
	if err != nil || !originVar {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.OriginIsInvalid)
		return err
	}
	appPkgRec := &models.AppPackageRecord{
		AppPkgId: packageId + tenantId,
	}

	readErr := c.Db.ReadData(appPkgRec, util.AppPkgId)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound, util.RecordDoesNotExist)
		return readErr
	}
	syncStatus := true
	if origin == "MEPM" {
		syncStatus = false
	}

	appPkgHostRecord := &models.AppPackageHostRecord{
		PkgHostKey: packageId + tenantId + hostIp,
		HostIp:     hostIp,
		AppPkgId:   packageId,
		Status:     distributionStatus,
		TenantId:   tenantId,
		Error:      "",
		SyncStatus: syncStatus,
		Origin:     origin,
		AppPackage: appPkgRec,
	}

	count, err := c.Db.QueryCountForTable("app_package_host_record", util.TenantId, tenantId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	if count >= util.MaxNumberOfRecords {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError,
			"Maximum number of app package records are exceeded for given tenant")
		return errors.New("maximum number of app package host records are exceeded for given tenant")
	}

	log.Info("Add app package host record: %+v", appPkgHostRecord)
	err = c.Db.InsertOrUpdateData(appPkgHostRecord, util.PkgHostKey)
	if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
		log.Error("Failed to save app package host record to database.")
		return err
	}
	return nil
}

// @Title Distribution status
// @Description Distribute Package
// @Param   access_token  header     string true   "access token"
// @Param   packageId     header     string true   "package ID"
// @Success 200 ok
// @Failure 400 bad request
// @router /packages/:packageId [get]
func (c *LcmController) DistributionStatus() {
	log.Info("Distribute status request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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

	tenantId, packageId, err := c.getInputParametersForDistributionStatus(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	var appPkgRecords []*models.AppPackageRecord
	if packageId == "" {
		count, _ := c.Db.QueryTable(util.AppPackageRecordId, &appPkgRecords, util.TenantId, tenantId)
		if count == 0 {
			c.writeErrorResponse(util.RecordDoesNotExist, util.StatusNotFound)
			return
		}
	} else {
		count, _ := c.Db.QueryTable(util.AppPackageRecordId, &appPkgRecords, util.AppPkgId, packageId + tenantId)
		if count == 0 {
			c.writeErrorResponse(util.RecordDoesNotExist, util.StatusNotFound)
			return
		}
	}

	for _, appPkgRecord := range appPkgRecords {
		_, _ = c.Db.LoadRelated(appPkgRecord, util.MecHostInfo)
	}

	var appPkgs []models.AppPackageStatusRecord
	for _, appPkgRecord := range appPkgRecords {

		var p models.AppPackageStatusRecord
		p.AppId = appPkgRecord.AppId
		p.PackageId = appPkgRecord.PackageId
		p.AppProvider = appPkgRecord.AppProvider
		p.AppPkgAffinity = appPkgRecord.AppPkgAffinity
		p.AppPkgDesc = appPkgRecord.AppPkgDesc
		p.AppPkgName = appPkgRecord.AppPkgName
		p.AppPkgVersion = appPkgRecord.AppPkgVersion
		p.CreatedTime = appPkgRecord.CreatedTime
		p.ModifiedTime = appPkgRecord.ModifiedTime

		for _, appPkgHost := range appPkgRecord.MecHostInfo {
            //fill app package host info
			var ph models.AppPackageHostStatusRecord
			ph.HostIp = appPkgHost.HostIp
			ph.Error = appPkgHost.Error
			ph.Status = appPkgHost.Status
			p.MecHostInfo = append(p.MecHostInfo, ph)
		}
		appPkgs = append(appPkgs, p)
	}

	res, err := json.Marshal(appPkgs)
	if err != nil {
		c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
		return
	}

	_, err = c.Ctx.ResponseWriter.Write(res)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}

	c.handleLoggingForSuccess(clientIp, "Query app package records successful")
    return
}

// Get input parameters for distribution status
func (c *LcmController) getInputParametersForDistributionStatus(clientIp string) (string, string, error) {
	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		return "", "", err
	}

	packageId, err := c.getUrlPackageId(clientIp)
	if err != nil {
		return "", "", err
	}
	return 	tenantId, packageId, err
}

// Get input parameters for upload package
func (c *LcmController) getInputParametersForUploadPkg(clientIp string) (string, string, string, error) {

	appId, err := c.getAppId(clientIp)
	if err != nil {
		return "", "", "", err
	}
	if len(appId) == 0 {
		appId = util.GenerateUUID()
	}

	packageId, err := c.getPackageId(clientIp)
	if err != nil {
		return "", "", "", err
	}

	if len(packageId) == 0 {
		packageId = appId +  util.GenerateUUID()
	}

	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		return "", "", "", err
	}
	return appId, packageId, tenantId, nil
}

// @Title Sync app package records
// @Description Sync app package records
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/packages/sync_updated [get]
func (c *LcmController) SynchronizeAppPackageUpdatedRecord() {
	log.Info("Sync app package request received.")

	var appPackages []*models.AppPackageRecord
	var appPackagesSync []*models.AppPackageRecord

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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

	err = util.ValidateAccessToken(accessToken, []string{util.MecmAdminRole}, tenantId)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}

	_, _ = c.Db.QueryTable("app_package_record", &appPackages, "")
	for _, appPackage := range appPackages {
		if strings.EqualFold(appPackage.Origin, "mepm") {
			_, _ = c.Db.LoadRelated(appPackage, util.MecHostInfo)
			for _, appPkgMecHostInfo := range appPackage.MecHostInfo {
				if !appPkgMecHostInfo.SyncStatus {
					appPackagesSync = append(appPackagesSync, appPackage)
				}
			}
		}
	}

	err = c.sendAppPkgSyncRecords(appPackagesSync, clientIp)
	if err != nil {
		return
	}

	err = c.insertAppPackageRec(appPackagesSync)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(clientIp, "Application packages synchronization is successful")
}

// @Title Sync app package stale records
// @Description Sync mec host stale records
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/packages/sync_deleted [get]
func (c *LcmController) SynchronizeAppPackageStaleRecord() {
	log.Info("Sync mec host stale request received.")

	var appPackageStaleRecs []models.AppPackageStaleRec
	var appPkgHostStaleRecs []models.AppPackageHostStaleRec
	var appDistPkgHostStaleRecords models.AppDistPkgHostStaleRecords


	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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

	err = util.ValidateAccessToken(accessToken, []string{util.MecmAdminRole}, tenantId)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}
	_, _ = c.Db.QueryTable("app_package_stale_rec", &appPackageStaleRecs, "")
	_, _ = c.Db.QueryTable("app_package_host_stale_rec", &appPkgHostStaleRecs, "")

	appDistPkgHostStaleRecords.AppPackageStaleRecs = append(appDistPkgHostStaleRecords.AppPackageStaleRecs, appPackageStaleRecs...)
	appDistPkgHostStaleRecords.AppPackageHostStaleRec = append(appDistPkgHostStaleRecords.AppPackageHostStaleRec, appPkgHostStaleRecs...)

	res, err := json.Marshal(appDistPkgHostStaleRecords)
	if err != nil {
		c.writeErrorResponse("failed to marshal request", util.BadRequest)
		return
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)
	_, err = c.Ctx.ResponseWriter.Write(res)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	for _, appPackageStaleRec := range appPackageStaleRecs {
		err = c.Db.DeleteData(&appPackageStaleRec, util.AppPkgId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
			return
		}
	}

	for _, appPkgHostStaleRec := range appPkgHostStaleRecs {
		err = c.Db.DeleteData(&appPkgHostStaleRec, util.PkgId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
			return
		}
	}

	c.handleLoggingForSuccess(clientIp, "Stale app package records synchronization is successful")
}

// Process upload package
func (c *LcmController) processUploadPackage(hosts models.DistributeRequest,
	clientIp, tenantId, packageId, accessToken string) error {
	for _, hostIp := range hosts.HostIp {
		vim, err := c.getVim(clientIp, hostIp)
		if err != nil {
			return err
		}

		pluginInfo := util.GetPluginInfo(vim)
		client, err := pluginAdapter.GetClient(pluginInfo)
		if err != nil {
			c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
			return err
		}

		pkgFilePath := PackageFolderPath + tenantId + "/" + packageId + "/" + packageId + ".csar"

		adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
		status, err := adapter.UploadPackage(tenantId, pkgFilePath, hostIp, packageId, accessToken)
		//c.deletePackage(path.Dir(pkgFilePath))
		if err != nil {
			c.HandleLoggingForFailure(clientIp, err.Error())
			err = c.updateAppPkgRecord(hosts, clientIp, tenantId, packageId, hostIp, "Error")
			return err
		}
		if status == util.Failure {
			c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToUploadToPlugin)
			err = errors.New("failed to upload package to plugin")
			return err
		}

		err = c.updateAppPkgRecord(hosts, clientIp, tenantId, packageId, hostIp, "Distributed")
		if err != nil {
			return err
		}
	}
	return nil
}

// Update app package records
func (c *LcmController) updateAppPkgRecord(hosts models.DistributeRequest,
	clientIp, tenantId, packageId, hostIp, status string) error {
	err := c.insertOrUpdateTenantRecord(clientIp, tenantId)
	if err != nil {
		return err
	}

	err = c.insertOrUpdateAppPkgHostRecord(hostIp, clientIp, tenantId, packageId,
		status, hosts.Origin)
	if err != nil {
		return err
	}
	return nil
}

// Get input parameters for delete package on host
func (c *LcmController) getInputParametersForDelPkgOnHost(clientIp string) (string, string, string, error) {
	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		return "", "", "", err
	}

	packageId, err := c.getUrlPackageId(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		return "", "", "", err
	}

	hostIp, err := c.getUrlHostIP(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		return "", "", "", err
	}

	return tenantId, packageId, hostIp, nil
}

// Get vim and host ip from package host record
func (c *LcmController) getVimAndHostIpFromPkgHostRec(clientIp, packageId, tenantId, hostIp string) (string, string, error) {
	appPkgRecord, err := c.getAppPackageRecord(packageId, tenantId, clientIp)
	if err != nil {
		return "", "", err
	}

	appPkgHostRecord, err := c.getAppPackageHostRecord(hostIp, appPkgRecord.PackageId, appPkgRecord.TenantId, clientIp)
	if err != nil {
		return "", "", err
	}

	vim, err := c.getVim(clientIp, appPkgHostRecord.HostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return "", "", err
	}
	return appPkgHostRecord.HostIp, vim, err
}

// Delete application pacakge records
func (c *LcmController) delAppPkgRecords(clientIp, packageId, tenantId, hostIp string) error {
	appPkgHostRec := &models.AppPackageHostRecord{
		PkgHostKey: packageId + tenantId + hostIp,
	}

	err := c.Db.ReadData(appPkgHostRec, util.PkgHostKey)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			util.RecordDoesNotExist)
		return err
	}
	var origin = appPkgHostRec.Origin

	err = c.deleteAppPackageHostRecord(hostIp, packageId, tenantId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	err = c.deleteTenantRecord(clientIp, tenantId)
	if err != nil {
		return err
	}

	appPackageHostStaleRec := &models.AppPackageHostStaleRec{
		PackageId: packageId,
		TenantId: tenantId,
		HostIp:   hostIp,
	}

	if strings.EqualFold(origin, "mepm") {
		err = c.Db.InsertOrUpdateData(appPackageHostStaleRec, util.PkgId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
			return err
		}
	}
	return nil
}

// Insert app package records
func (c *LcmController) insertAppPackageRec(appPackagesSync []*models.AppPackageRecord) error {
	for _, appPackage := range appPackagesSync {
		for _, appPkgMecHostInfo := range appPackage.MecHostInfo {
			appPkgMecHostInfo.SyncStatus = true
			err := c.Db.InsertOrUpdateData(appPkgMecHostInfo, util.PkgHostKey)
			if err != nil && err.Error() != util.LastInsertIdNotSupported {
				log.Error("Failed to save app package mec host record to database.")
				return err
			}
		}

		appPackage.SyncStatus = true
		err := c.Db.InsertOrUpdateData(appPackage, util.AppPkgId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			log.Error("Failed to save app package host record to database.")
			return err
		}
	}
	return nil
}

// Send application package records
func (c *LcmController) sendAppPkgSyncRecords(appPackagesSync []*models.AppPackageRecord, clientIp string) error {
	var appPackageRec []models.AppPackageRecordInfo
	var appPackageSyncRecords models.AppPackagesUpdatedRecords

	res, err := json.Marshal(appPackagesSync)
	if err != nil {
		c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
		return err
	}
	err = json.Unmarshal(res, &appPackageRec)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return err
	}

	appPackageSyncRecords.AppPackagesUpdatedRecs = append(appPackageSyncRecords.AppPackagesUpdatedRecs, appPackageRec...)

	response, err := json.Marshal(appPackageSyncRecords)
	if err != nil {
		c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
		return err
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)
	_, err = c.Ctx.ResponseWriter.Write(response)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return err
	}
	return nil
}

// Process delete packages
func (c *LcmController) processDeletePackage(clientIp, packageId, tenantId, accessToken string) error {
	var appPkgRecords []*models.AppPackageRecord
	_, _ = c.Db.QueryTable(util.AppPackageRecordId, &appPkgRecords, util.AppPkgId, packageId + tenantId)

	for _, appPkgRecord := range appPkgRecords {
		_, _ = c.Db.LoadRelated(appPkgRecord, util.MecHostInfo)
	}

	for _, appPkgRecord := range appPkgRecords {
		for _, appPkgHost := range appPkgRecord.MecHostInfo {
			err := c.deletePackage(appPkgHost, clientIp, packageId, accessToken)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Delete application package records
func (c *LcmController) deleteAppPkgRecords(packageId, tenantId, clientIp string) error {
	appPkgRec := &models.AppPackageRecord{
		AppPkgId: packageId + tenantId,
	}

	err := c.Db.ReadData(appPkgRec, util.AppPkgId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound, util.RecordDoesNotExist)
		return err
	}
	var origin = appPkgRec.Origin

	err = c.deleteAppPackageRecord(packageId, tenantId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	err = c.deleteTenantRecord(clientIp, tenantId)
	if err != nil {
		return err
	}

	appPackageStaleRec := &models.AppPackageStaleRec{
		AppPkgId: packageId,
		TenantId: tenantId,
	}

	if strings.EqualFold(origin, "mepm") {
		err = c.Db.InsertOrUpdateData(appPackageStaleRec, util.AppPkgId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
			return err
		}
	}
	return nil
}

// Send delete package
func (c *LcmController) deletePackage(appPkgHost *models.AppPackageHostRecord,
	clientIp, packageId, accessToken string) error {
	vim, err := c.getVim(clientIp, appPkgHost.HostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return err
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.DeletePackage(appPkgHost.TenantId, appPkgHost.HostIp, packageId, accessToken)
	if err != nil {
		c.HandleLoggingForFailure(clientIp, err.Error())
		return err
	}
	return nil
}