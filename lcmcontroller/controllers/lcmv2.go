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
	"bytes"
	"encoding/json"
	"errors"
	"github.com/ghodss/yaml"
	"io"
	"io/ioutil"
	"lcmcontroller/config"
	"lcmcontroller/models"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

// Lcm Controller
type LcmControllerV2 struct {
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
func (c *LcmControllerV2) UploadConfigV2() {
	log.Info("Add configuration request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
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
		c.HandleForErrorCode(clientIp, util.StatusNotFound,
			util.MecHostRecDoesNotExist,util.ErrCodeHostNotExist)
		return
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedGetPlugin)
		return
	}

	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.UploadConfig(file, hostIp, accessToken)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodeFailedPlugin)
		return
	}

	hostInfoRec.ConfigUploadStatus = "Uploaded"
	err = c.Db.InsertOrUpdateData(hostInfoRec, util.HostIp)
	if err != nil && err.Error() != util.LastInsertIdNotSupported {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.InsertDBWithError,
			util.ErrCodeFailedToInsert)
		log.Error("Failed to save mec host info record to database.")
		return
	}

	returnContent, _ := handleSuccessReturn(nil, util.UploadConfigSuccess)
	c.handleLoggingForSuccess(returnContent, clientIp, util.UploadConfigSuccess)
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
func (c *LcmControllerV2) UploadPackageV2() {
	log.Info("Upload application package request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)
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
		c.HandleForErrorCode(clientIp, util.BadRequest, "Upload config file error",
			util.ErrCodeFileCanNotRead)
		return
	}

	err = util.ValidateFileExtensionCsar(header.Filename)
	if err != nil || len(header.Filename) > util.MaxFileNameSize {
		util.ClearByteArray(bKey)
		c.HandleForErrorCode(clientIp, util.BadRequest,
			"File shouldn't contains any extension or filename is larger than max size",
			util.ErrCodeFailedToSaveFile)
		return
	}

	err = util.ValidateFileSize(header.Size, util.MaxAppPackageFile)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleForErrorCode(clientIp, util.BadRequest, "File size is larger than max size", util.ErrCodeFileToBig)
		return
	}

	pkgFilePath, err := c.saveApplicationPackage(clientIp, tenantId, packageId, header, file)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedToSaveFile)
		return
	}
	pkgDir, err := extractCsarPackage(pkgFilePath)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedToExtract)
		return
	}

	pkgDetails, err := c.getPackageDetailsFromPackage(clientIp, pkgDir)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleForErrorCode(clientIp, util.BadRequest, util.GetPackageDetailsFailed, util.ErrCodeFailedGetDetails)
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

	appPkgResp := &models.AppPackageResponse{
		AppId:    appId,
		PackageId: packageId,
	}
	c.handleLoggingForSuccess(appPkgResp, clientIp, util.UploadPackageSuccess)
}

func (c *LcmControllerV2) handleLoggingForSuccess(object interface{}, clientIp string, msg string) {
	log.Info("Response message for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Success: " + msg + ".]")
	returnContent, _ := handleSuccessReturn(object, util.UploadConfigSuccess)
	c.Ctx.ResponseWriter.Write(returnContent)
	c.Ctx.ResponseWriter.WriteHeader(util.SuccessCode)
	c.ServeJSON()
}

// Get input parameters for upload package
func (c *LcmControllerV2) getInputParametersForUploadPkg(clientIp string) (string, string, string, error) {

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

// Get app Id
func (c *LcmControllerV2) getAppId(clientIp string) (string, error) {
	appId := c.GetString("appId")
	if appId != "" {
		if len(appId) > 32 {
			c.HandleForErrorCode(clientIp, util.BadRequest, util.AppIdIsNotValid, util.ErrCodeAppIdInvalid)
			return "", errors.New("app id length exceeds max limit")
		}
		return appId, nil
	}
	return "", nil
}

// Get Package Id
func (c *LcmControllerV2) getPackageId(clientIp string) (string, error) {
	packageId := c.GetString("packageId")
	if packageId != "" {
		if len(packageId) > 64 {
			c.HandleForErrorCode(clientIp, util.BadRequest, util.PackageIdIsInvalid, util.ErrCodePackageIdInvalid)
			return "", errors.New("package id length exceeds max limit")
		}
		return packageId, nil
	}
	return "", nil
}

// Get origin
func (c *LcmControllerV2) getOrigin(clientIp string) (string, error) {
	origin := c.GetString("origin")
	originVar, err := util.ValidateName(origin, util.NameRegex)
	if err != nil || !originVar {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.OriginIsInvalid, util.ErrCodeOriginInvalid)
		return "", errors.New(util.OriginIsInvalid)
	}
	return origin, nil
}

func (c *LcmControllerV2) saveApplicationPackage(clientIp string, tenantId string, packageId string,
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

// Create package path
func (c *LcmControllerV2) createPackagePath(pkgPath string, clientIp string, file multipart.File) error {

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, "Failed to copy csar file",
			util.ErrCodeFailedToSaveFile)
		return err
	}

	newFile, err := os.Create(pkgPath)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, "Failed to create package path",
			util.ErrCodeFailedToSaveFile)
		return err
	}
	defer newFile.Close()
	if _, err := newFile.Write(buf.Bytes()); err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, "Failed to write csar file",
			util.ErrCodeFailedToSaveFile)
		return err
	}
	return nil
}

// Get Package Id from url
func (c *LcmControllerV2) getUrlPackageId(clientIp string) (string, error) {
	packageId := c.Ctx.Input.Param(":packageId")
	if packageId != "" {
		//uuid, err := util.IsValidUUID(packageId)
		if len(packageId) > 64 {
			c.HandleForErrorCode(clientIp, util.BadRequest, util.PackageIdIsInvalid, util.ErrCodePackageIdInvalid)
			return "", errors.New("invalid package id")
		}
		return packageId, nil
	}
	return "", nil
}

// Get application package details
func (c *LcmControllerV2) getPackageDetailsFromPackage(clientIp string,
	packageDir string) (models.AppPkgDetails, error) {

	var pkgDetails models.AppPkgDetails
	mf, err := c.getFileContainsExtension(clientIp, packageDir, ".mf")
	if err != nil {
		log.Error("failed to find mf file, check if mf file exist.")
		c.HandleForErrorCode(clientIp, util.BadRequest, "failed to find mf file, check if mf file exist.",
			util.ErrCodeFailedGetDetails)
		return pkgDetails, errors.New("failed to find mf file")
	}

	mfYaml, err := os.Open(mf)
	if err != nil {
		log.Error("failed to open mf file")
		return pkgDetails, errors.New("failed to read mf file")
	}
	defer mfYaml.Close()

	mfFileBytes, _ := ioutil.ReadAll(mfYaml)

	data, err := yaml.YAMLToJSON(mfFileBytes)
	if err != nil {
		log.Error(util.FailedToCovertYamlToJson + ", pls check mf file if struct is not correct.")
		return pkgDetails, errors.New(util.FailedToCovertYamlToJson)
	}

	err = json.Unmarshal(data, &pkgDetails)
	if err != nil {
		log.Error(util.UnMarshalError + ", pls check if app version or desc was incorrectly set to a number.")
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.UnMarshalError,
			util.ErrCodeFailedGetDetails)
		return pkgDetails, err
	}
	return pkgDetails, nil
}

// get file with extension
func (c *LcmControllerV2) getFileContainsExtension(clientIp string, pkgDir string, ext string) (string, error) {
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

// Get in put parameters for upload configuration
func (c *LcmControllerV2) getInputParametersForUploadCfg(clientIp string) (hostIp string,
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
		c.HandleForErrorCode(clientIp, util.BadRequest, "Upload config file error",
			util.ErrCodeFileCanNotRead)
		return hostIp, vim, file, err
	}

	err = util.ValidateFileExtensionEmpty(header.Filename)
	if err != nil || len(header.Filename) > util.MaxFileNameSize {
		c.HandleForErrorCode(clientIp, util.BadRequest,
			"File shouldn't contains any extension or filename is larger than max size",
			util.ErrCodeFileNameTooLang)
		return hostIp, vim, file, err
	}

	err = util.ValidateFileSize(header.Size, util.MaxConfigFile)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, "File size is larger than max size",
			util.ErrCodeFileToBig)
		return hostIp, vim, file, err
	}

	err = c.validateYamlFile(clientIp, file)
	if err != nil {
		return hostIp, vim, file, err
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, err.Error(),util.ErrCodeFailedToSaveFile)
		return hostIp, vim, file, err
	}
	return hostIp, vim, file, nil
}


// Validate kubeconfig file
func (c *LcmControllerV2) validateYamlFile(clientIp string, file multipart.File) error {

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, "Failed to copy file into buffer",
			util.ErrCodeFailedToSaveFile)
		return err
	}

	_, err := yaml.YAMLToJSON(buf.Bytes())
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, "KubeConfig file validation is failed",
			util.ErrCodeFileCanNotRead)
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
func (c *LcmControllerV2) RemoveConfigV2() {
	log.Info("Delete configuration request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
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
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedGetPlugin)
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
	c.handleLoggingForSuccess(nil, clientIp, "Remove config is successful")
}

// Get vim name
func (c *LcmControllerV2) getVim(clientIp string, hostIp string) (string, error) {

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

// Get in put parameters for remove configuration
func (c *LcmControllerV2) getInputParametersForRemoveCfg(clientIp string) (string, string, *models.MecHost, error) {
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		return "", "", &models.MecHost{}, err
	}

	hostInfoRec := &models.MecHost{
		MecHostId: hostIp,
	}

	readErr := c.Db.ReadData(hostInfoRec, util.HostIp)
	if readErr != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound,
			util.MecHostRecDoesNotExist, util.ErrCodeHostNotExist)
		return "", "", hostInfoRec, err
	}

	vim, err := c.getVim(clientIp, hostIp)
	if err != nil {
		return "", "", hostInfoRec, err
	}

	return hostIp, vim, hostInfoRec, err
}


// Get host IP
func (c *LcmControllerV2) getHostIP(clientIp string) (string, error) {
	hostIp := c.GetString("hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.HostIpIsInvalid,util.ErrCodeInvalidHost)
		return "", err
	}
	return hostIp, nil
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
func (c *LcmControllerV2) InstantiateV2() {
	log.Info("Application instantiation request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)

	var req models.InstantiateRequest
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &req)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, err.Error(), util.ErrCodeInvalidRequest)
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
		c.HandleForErrorCode(clientIp, util.BadRequest, util.OriginIsInvalid, util.ErrCodeAppNameInvalid)
		return
	}

	appParams := &models.AppInfoParams{
		AppInstanceId: appInsId,
		MecHost: hostIp,
		TenantId: tenantId,
		AppPackageId: packageId,
		AppName: appName,
		ClientIP: clientIp,
		AccessToken: accessToken,
	}

	doPrepareParams(c, appParams, bKey, req)
	doInstantiate(c, appParams, bKey, req)
}

func (c *LcmControllerV2) validateToken(accessToken string, req models.InstantiateRequest,  clientIp string) (string, string, string, string, string, error) {

	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.RequestBodyTooLarge, util.ErrCodeBodyTooLarge)
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

func (c *LcmControllerV2) ValidateInstantiateInputParameters(clientIp string, req models.InstantiateRequest) (string, string, string, string, string, error) {

	hostIp := req.HostIp
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.HostIpIsInvalid, util.ErrCodeInvalidHost)
		return "", "", "",  "", "", err
	}

	packageId := req.PackageId
	if len(packageId) == 0 {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.PackageIdIsInvalid, util.ErrCodePackageIdInvalid)
		return "", "", "",  "", "", err
	}

	if len(packageId) > 64 {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.PackageIdIsInvalid, util.ErrCodePackageIdInvalid)
		return "", "", "", "", "", errors.New("package id length exceeds max limit")
	}

	appName := req.AppName
	name, err := util.ValidateName(appName, util.NameRegex)
	if err != nil || !name {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.AppNameIsNotValid, util.ErrCodeAPPNAmeInvalid)
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

func doPrepareParams(c *LcmControllerV2, params *models.AppInfoParams, bKey []byte, req models.InstantiateRequest) {
	appPkgHostRecord := &models.AppPackageHostRecord{
		PkgHostKey: params.AppPackageId + params.TenantId + params.MecHost,
	}

	readErr := c.Db.ReadData(appPkgHostRecord, util.PkgHostKey)
	if readErr != nil {
		c.HandleForErrorCode(params.ClientIP, util.StatusNotFound,
			"App package host record not exists", util.ErrCodeNotFoundInDB)
		util.ClearByteArray(bKey)
		return
	}
	if appPkgHostRecord.Status != "Distributed" {
		c.HandleForErrorCode(params.ClientIP, util.BadRequest,
			"application package distribution status is:" + appPkgHostRecord.Status, util.ErrCodePackDistributed)
		util.ClearByteArray(bKey)
		return
	}


	appInfoRecord := &models.AppInfoRecord{
		AppInstanceId: params.AppInstanceId,
	}

	readErr = c.Db.ReadData(appInfoRecord, util.AppInsId)
	if readErr == nil {
		c.HandleForErrorCode(params.ClientIP, util.BadRequest,
			"App instance info record already exists",util.ErrCodeInstanceIsExist)
		util.ClearByteArray(bKey)
		return
	}

}

func doInstantiate(c *LcmControllerV2, params *models.AppInfoParams, bKey []byte, req models.InstantiateRequest) {
	vim, err := c.getVim(params.ClientIP, params.MecHost)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleForErrorCode(params.ClientIP, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedGetPlugin)
		return
	}
	err, acm := processAkSkConfig(params.AppInstanceId, params.AppName, &req, params.ClientIP, params.TenantId)
	if err != nil {
		c.HandleForErrorCode(params.ClientIP, util.StatusInternalServerError, err.Error(), util.ErrCodeProcessAkSk)
		util.ClearByteArray(bKey)
		return
	}

	err = c.insertOrUpdateTenantRecord(params.ClientIP, params.TenantId)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	var appInfoParams models.AppInfoRecord
	appInfoParams.AppInstanceId = params.AppInstanceId
	appInfoParams.MecHost = params.MecHost

	appInfoParams.TenantId = params.TenantId
	appInfoParams.AppPackageId = params.AppPackageId
	appInfoParams.AppName = params.AppName
	appInfoParams.Origin = req.Origin

	err = c.insertOrUpdateTenantRecord(params.ClientIP, appInfoParams.TenantId)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	err, status := adapter.Instantiate(params.TenantId, params.AccessToken, params.AppInstanceId, req)
	util.ClearByteArray(bKey)
	if err != nil {
		c.handleErrorForInstantiateApp(acm, params.ClientIP, params.AppInstanceId, params.TenantId)
		c.HandleForErrorCode(params.ClientIP, util.StatusInternalServerError, err.Error(), util.ErrCodeFailedPlugin)
		return
	}
	if status == util.Failure {
		c.handleErrorForInstantiateApp(acm, params.ClientIP, params.AppInstanceId, params.TenantId)
		c.HandleForErrorCode(params.ClientIP, util.StatusInternalServerError, util.FailedToInstantiate,
			util.ErrCodePluginInstFailed)
		err = errors.New(util.FailedToInstantiate)
		return
	}
	c.handleLoggingForSuccess(nil, params.ClientIP, "Application instantiated successfully")
}

// Insert or update tenant info record
func (c *LcmControllerV2) insertOrUpdateTenantRecord(clientIp, tenantId string) error {
	tenantRecord := &models.TenantInfoRecord{
		TenantId: tenantId,
	}

	count, err := c.Db.QueryCount("tenant_info_record")
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(),util.ErrCodeReportByDB)
		return err
	}

	if count >= util.MaxNumberOfTenantRecords {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError,
			util.TenantNumUpToMax, util.ErrCodeTenantNumUpToMax)
		return errors.New("maximum number of tenant records are exceeded")
	}

	err = c.Db.InsertOrUpdateData(tenantRecord, util.TenantId)
	if err != nil && err.Error() != util.LastInsertIdNotSupported {
		log.Error("Failed to save tenant record to database.")
		return err
	}
	return nil
}


// Insert or update application package record
func (c *LcmControllerV2) insertOrUpdateAppPkgRecord(appId, clientIp, tenantId,
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
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(),util.ErrCodeNotFoundInDB)
		return err
	}

	if count >= util.MaxNumberOfRecords {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PackageNumUpToMax,
			util.ErrCodePackUptoMaxNumber)
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


func (c *LcmControllerV2) handleErrorForInstantiateApp(acm config.AppConfigAdapter,
	clientIp, appInsId, tenantId string) {
	err := acm.DeleteAppAuthConfig(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteAuthCfgFail)
		return
	}
	err = c.deleteAppInfoRecord(appInsId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeFailedDeleteData)
		return
	}

	err = c.deleteTenantRecord(clientIp, tenantId)
	if err != nil {
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
func (c *LcmControllerV2) TerminateV2() {
	log.Info("Application termination request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
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
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteAuthCfgFail)
		return
	}

	var origin = appInfoRecord.Origin

	err = c.deleteAppInfoRecord(appInsId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeFailedDeleteData)
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

	c.handleLoggingForSuccess(nil, clientIp, "Termination is successful")
	c.ServeJSON()
}

// Handle logging
func (c *LcmControllerV2) HandleLoggingForFailure(clientIp string, errorString string) {
	if strings.Contains(errorString, util.Forbidden) {
		c.HandleForErrorCode(clientIp, util.StatusForbidden, util.Forbidden, util.ErrCodeForbidden)
	} else if strings.Contains(errorString, util.AccessTokenIsInvalid) {
		c.HandleForErrorCode(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, util.ErrCodeTokenInvalid)
	} else {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, errorString,util.ErrCodeInternalServer)
	}
}

// @Title Query
// @Description perform query operation
// @Param	tenantId	path 	string	true	"tenantId"
// @Param	appInstanceId   path 	string	true	"appInstanceId"
// @Param       access_token    header  string  true    "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/:appInstanceId [get]
func (c *LcmControllerV2) QueryV2() {
	log.Info("Application query request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
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
		c.HandleForErrorCode(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, util.ErrCodeTokenInvalid)
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
			c.HandleForErrorCode(clientIp, util.StatusNotFound, err.Error(), util.ErrCodeNotFoundInPlugin)
			return
		}
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrorReportByPlugin)
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeFailResponse)
		return
	}
	c.handleLoggingForSuccess(nil, clientIp, "Query workload statistics is successful")
}

// @Title Query kpi
// @Description perform query kpi operation
// @Param	hostIp          path 	string	true	    "hostIp"
// @Param	tenantId	    path 	string	true	    "tenantId"
// @Param   access_token    header  string  true        "access token"
// @Success 200 ok
// @Failure 403 bad request
// @router /tenants/:tenantId/hosts/:hostIp/kpi [get]
func (c *LcmControllerV2) QueryKPI() {
	log.Info("Application query kpi request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
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
		c.HandleLoggingForTokenFailure(clientIp, util.AccessTokenIsInvalid)
		util.ClearByteArray(bKey)
		return
	}
	util.ClearByteArray(bKey)

	hostIp, err := c.getUrlHostIP(clientIp)
	if err != nil {
		return
	}

	vim, err := c.getVim(clientIp, hostIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.getPluginAdapter("", clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	response, err := adapter.QueryKPI(accessToken, hostIp)
	util.ClearByteArray(bKey)
	if err != nil {
		res := strings.Contains(err.Error(), util.NotFound)
		if res {
			c.HandleForErrorCode(clientIp, util.StatusNotFound, err.Error(), util.ErrCodeNotFoundInPlugin)
			return
		}
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrorReportByPlugin)
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeFailResponse)

		return
	}
	c.handleLoggingForSuccess(nil, clientIp, "Query kpi is successful")
}

// Get host IP from url
func (c *LcmControllerV2) getUrlHostIP(clientIp string) (string, error) {
	hostIp := c.Ctx.Input.Param(":hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, "MecHost address is invalid from url",
			util.ErrCodeInvalidHost)
		return "", err
	}
	return hostIp, nil
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
func (c *LcmControllerV2) QueryMepCapabilities() {
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
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
		c.HandleLoggingForTokenFailure(clientIp, util.AccessTokenIsInvalid)
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
		c.HandleForErrorCode(clientIp, statusCode, "invalid mepCapabilities query", util.ErrCodeCallForMep)
		return
	}

	_, err = c.Ctx.ResponseWriter.Write([]byte(mepCapabilities))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeFailResponse)
		return
	}
	c.handleLoggingForSuccess(nil, clientIp, "Query mep capabilities is successful")
}

// Get mep capability id from url
func (c *LcmControllerV2) getUrlCapabilityId(clientIp string) (string, error) {
	capabilityId := c.Ctx.Input.Param(":capabilityId")
	err := util.ValidateMepCapabilityId(capabilityId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, "capability id is invalid from url",
			util.ErrCodeInvalidCapId)
		return "", err
	}
	return capabilityId, nil
}

// @Title GetWorkloadDescription
// @Description perform get workload description
// @Param	tenantId	    path 	string	true	"tenantId"
// @Param	appInstanceId   path 	string	true	"appInstanceId"
// @Param   access_token    header  string  true    "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/:appInstanceId/workload/events  [get]
func (c *LcmControllerV2) GetWorkloadDescription() {
	log.Info("Get workload description request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
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
		c.HandleForErrorCode(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, util.ErrCodeTokenInvalid)
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
			c.HandleForErrorCode(clientIp, util.StatusNotFound, err.Error(), util.ErrCodeGetWorkloadFailed)
			return
		}
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeGetWorkloadFailed)
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeFailResponse)
		return
	}
	c.handleLoggingForSuccess(nil, clientIp, "Workload description is successful")
}

// @Title Sync app instances records
// @Description Sync app instances records
// @Param   tenantId    path 	string	    true   "tenantId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/sync_updated [get]
func (c *LcmControllerV2) SynchronizeUpdatedRecordV2() {
	log.Info("Sync app instances request received.")

	var appInstances []models.AppInfoRecord
	var appInstancesSync []models.AppInfoRecord
	var appInstanceSyncRecords models.AppInfoUpdatedRecords
	var appInstanceRes []models.AppInfoRec

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
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
		c.HandleForErrorCode(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, util.ErrCodeTokenInvalid)
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
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeFailResponse)
		return
	}

	for _, appInstance := range appInstancesSync {
		appInstance.SyncStatus = true
		err = c.Db.InsertOrUpdateData(&appInstance, util.AppInsId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			log.Error(util.FailedToSaveAppInfo, util.ErrCodeSaveAppInfoFailed)
			return
		}
	}
	c.handleLoggingForSuccess(nil, clientIp, "AppInstance synchronization is successful")
}

// @Title Sync app instances stale records
// @Description Sync app instances stale records
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/sync_deleted [get]
func (c *LcmControllerV2) SynchronizeStaleRecordV2() {
	log.Info("Sync app instances stale request received.")

	var appInstStaleRecs []models.AppInstanceStaleRec
	var appInstanceStaleRecords models.AppInstanceStaleRecords

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
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
		c.HandleForErrorCode(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, util.ErrCodeTokenInvalid)
		return
	}
	_, _ = c.Db.QueryTable("app_instance_stale_rec", &appInstStaleRecs, "")

	appInstanceStaleRecords.AppInstanceStaleRecs = append(appInstanceStaleRecords.AppInstanceStaleRecs, appInstStaleRecs...)
	res, err := json.Marshal(appInstanceStaleRecords)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.FailedToMarshal, util.ErrCodeFailedToMarshal)
		return
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)
	_, err = c.Ctx.ResponseWriter.Write(res)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeFailResponse)
		return
	}
	for _, appInstStaleRec := range appInstStaleRecs {
		err = c.Db.DeleteData(&appInstStaleRec, util.AppInsId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(),util.ErrCodeFailedDeleteData)
			return
		}
	}
	c.handleLoggingForSuccess(nil, clientIp, "Stale appInstance records synchronization is successful")
}

// @Title Sync app package stale records
// @Description Sync mec host stale records
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/packages/sync_deleted [get]
func (c *LcmControllerV2) SynchronizeAppPackageStaleRecordV2() {
	log.Info("Sync mec host stale request received.")

	var appPackageStaleRecs []models.AppPackageStaleRec
	var appPkgHostStaleRecs []models.AppPackageHostStaleRec
	var appDistPkgHostStaleRecords models.AppDistPkgHostStaleRecords


	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
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
		c.HandleForErrorCode(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, util.ErrCodeTokenInvalid)
		return
	}
	_, _ = c.Db.QueryTable("app_package_stale_rec", &appPackageStaleRecs, "")
	_, _ = c.Db.QueryTable("app_package_host_stale_rec", &appPkgHostStaleRecs, "")

	appDistPkgHostStaleRecords.AppPackageStaleRecs = append(appDistPkgHostStaleRecords.AppPackageStaleRecs, appPackageStaleRecs...)
	appDistPkgHostStaleRecords.AppPackageHostStaleRec = append(appDistPkgHostStaleRecords.AppPackageHostStaleRec, appPkgHostStaleRecs...)

	res, err := json.Marshal(appDistPkgHostStaleRecords)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.FailedToMarshal, util.ErrCodeFailedToMarshal)
		return
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)
	_, err = c.Ctx.ResponseWriter.Write(res)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeFailResponse)
		return
	}
	for _, appPackageStaleRec := range appPackageStaleRecs {
		err = c.Db.DeleteData(&appPackageStaleRec, util.AppPkgId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(),util.ErrCodeFailedDeleteData)
			return
		}
	}

	for _, appPkgHostStaleRec := range appPkgHostStaleRecs {
		err = c.Db.DeleteData(&appPkgHostStaleRec, util.PkgId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(),util.ErrCodeFailedDeleteData)
			return
		}
	}

	c.handleLoggingForSuccess(nil, clientIp, "Stale app package records synchronization is successful")
}




func handleSuccessReturn(object interface{}, msg string) ([]byte, error) {
	result := &models.ReturnResponse{
		Data:    object,
		RetCode: 0,
		Message: msg,
		Params: nil,
	}

	resultValue, err := json.Marshal(result)
	return resultValue, err
}

func handleFailureReturn(object interface{}, retCode int, msg string, params []string) ([]byte, error) {
	result := &models.ReturnResponse{
		Data:    object,
		RetCode: retCode,
		Message: msg,
		Params: params,
	}

	resultValue, err := json.Marshal(result)
	return resultValue, err
}



func (c *LcmControllerV2) isPermitted(accessToken, clientIp string) (string, error) {
	var tenantId = ""
	var err error

	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.RequestBodyTooLarge, util.ErrCodeBodyTooLarge)
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

func (c *LcmControllerV2) getMecHostInfoRecord(hostIp string, clientIp string) (*models.MecHost, error) {
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

// Handled logging for token failure
func (c *LcmControllerV2) HandleLoggingForTokenFailure(clientIp, errorString string) {
	if errorString == util.Forbidden {
		c.HandleForErrorCode(clientIp, util.StatusForbidden, util.Forbidden, util.ErrCodeForbidden)
	} else {
		c.HandleForErrorCode(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, util.ErrCodeTokenInvalid)
	}
}

func (c *LcmControllerV2) getPluginAdapter(_, clientIp string, vim string) (*pluginAdapter.PluginAdapter,
	error) {
	var pluginInfo string

	pluginInfo = util.GetPluginInfo(vim)

	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
			util.ErrCodeFailedGetPlugin)
		return nil, err
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	return adapter, nil
}