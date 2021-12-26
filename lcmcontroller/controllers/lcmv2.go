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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lcmcontroller/config"
	"lcmcontroller/models"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"mime/multipart"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ghodss/yaml"

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
	_, err = c.IsPermitted(accessToken, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	hostIp, _, file, err := c.GetInputParametersForUploadCfg(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	vim, tenantId, err := c.TenantIdAndVim(hostIp, clientIp)
	if err != nil {
		return
	}

	hostInfoRec := &models.MecHost{
		MecHostId: hostIp,
	}

	readErr := c.Db.ReadData(hostInfoRec, util.HostIp)
	if readErr != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound,
			util.MecHostRecDoesNotExist, util.ErrCodeHostNotExist)
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
	_, err = adapter.UploadConfig(file, hostIp, accessToken, tenantId)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}

	hostInfoRec.ConfigUploadStatus = "Uploaded"
	err = c.Db.InsertOrUpdateData(hostInfoRec, util.HostIp)
	if err != nil && err.Error() != util.LastInsertIdNotSupported {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.InsertDBWithError,
			util.ErrCodeInsertDataFailed)
		log.Error("Failed to save mec host info record to database.")
		return
	}

	c.handleLoggingForSuccess(nil, clientIp, util.UploadConfigSuccess)
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
	_, err = c.IsPermitted(accessToken, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appId, packageId, tenantId, err := c.GetInputParametersForUploadPkg(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	origin, err := c.GetOrigin(clientIp)
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

	pkgFilePath, err := c.SaveApplicationPackage(clientIp, tenantId, packageId, header, file)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(),
			util.ErrCodeFailedToSaveFile)
		return
	}
	pkgDir, err := extractCsarPackage(pkgFilePath)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(),
			util.ErrCodeFailedToExtract)
		return
	}

	pkgDetails, err := c.GetPackageDetailsFromPackage(clientIp, pkgDir)
	if err != nil {
		util.ClearByteArray(bKey)
		c.HandleForErrorCode(clientIp, util.BadRequest, util.GetPackageDetailsFailed, util.ErrCodeFailedGetDetails)
		return
	}

	err = c.InsertOrUpdateTenantRecord(clientIp, tenantId)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	fmt.Println(pkgDetails)
	err = c.InsertOrUpdateAppPkgRecord(appId, clientIp, tenantId, packageId, pkgDetails, origin)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appPkgResp := &models.AppPackageResponse{
		AppId:     appId,
		PackageId: packageId,
	}
	c.handleLoggingForSuccess(appPkgResp, clientIp, util.UploadPackageSuccess)
}

func (c *LcmControllerV2) handleLoggingForSuccessV1(clientIp string, msg string) {
	log.Info("Response for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Success: " + msg + ".]")
}

func (c *LcmControllerV2) handleLoggingForSuccess(object interface{}, clientIp string, msg string) {
	log.Info("Response for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Success: " + msg + ".]")
	returnContent := handleSuccessReturn(object, msg)
	c.Data["json"] = returnContent
	c.Ctx.ResponseWriter.WriteHeader(util.SuccessCode)
	c.ServeJSON()
}

// Get input parameters for upload package
func (c *LcmControllerV2) GetInputParametersForUploadPkg(clientIp string) (string, string, string, error) {

	appId, err := c.GetAppId(clientIp)
	if err != nil {
		return "", "", "", err
	}
	
	if len(appId) == 0 {
		appId = util.GenerateUUID()
	}

	packageId, err := c.GetPackageId(clientIp)
	if err != nil {
		return "", "", "", err
	}

	if len(packageId) == 0 {
		packageId = appId + util.GenerateUUID()
	}

	tenantId, err := c.GetTenantId(clientIp)
	if err != nil {
		return "", "", "", err
	}
	return appId, packageId, tenantId, nil
}

// Get app Id
func (c *LcmControllerV2) GetAppId(clientIp string) (string, error) {
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
func (c *LcmControllerV2) GetPackageId(clientIp string) (string, error) {
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
func (c *LcmControllerV2) GetOrigin(clientIp string) (string, error) {
	origin := c.GetString("origin")
	originVar, err := util.ValidateName(origin, util.NameRegex)
	if err != nil || !originVar {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.OriginIsInvalid, util.ErrCodeOriginInvalid)
		return "", errors.New(util.OriginIsInvalid)
	}
	return origin, nil
}

func (c *LcmControllerV2) SaveApplicationPackage(clientIp string, tenantId string, packageId string,
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
	err = c.CreatePackagePath(pkgPath, clientIp, file)
	if err != nil {
		return "", err
	}

	return pkgPath, nil
}

// Create package path
func (c *LcmControllerV2) CreatePackagePath(pkgPath string, clientIp string, file multipart.File) error {

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
func (c *LcmControllerV2) GetUrlPackageId(clientIp string) (string, error) {
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
func (c *LcmControllerV2) GetPackageDetailsFromPackage(clientIp string,
	packageDir string) (models.AppPkgDetails, error) {

	var pkgDetails models.AppPkgDetails
	mf, err := c.GetFileContainsExtension(packageDir, ".mf")
	if err != nil {
		log.Error("failed to find mf file, check if mf file exist.")
		c.HandleForErrorCode(clientIp, util.BadRequest, "failed to find mf file, check if mf file exist.",
			util.ErrCodeFailedGetDetails)
		return pkgDetails, errors.New("failed to find mf file")
	}

	mfYaml, err := os.Open(mf)
	if err != nil {
		log.Error(util.FailedToReadMfFile)
		return pkgDetails, errors.New(util.FailedToReadMfFile)
	}
	defer mfYaml.Close()

	ReadMfKeyVal(mfYaml, &pkgDetails)
	return pkgDetails, nil
}

func ReadMfKeyVal(mfYaml *os.File, m *models.AppPkgDetails) {
	scanner := bufio.NewScanner(mfYaml)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		if checkLineStartWith(line, util.PkgDtlAppDescription) {
			m.App_package_description = GetValue(line)
		}
		if checkLineStartWith(line, util.PkgDtlAppClass) {
			m.App_class = GetValue(line)
		}
		if checkLineStartWith(line, util.PkgDtlAppVersion) {
			m.App_package_version = GetValue(line)
		}
		if checkLineStartWith(line, util.PkgDtlAppRlsTime) {
			m.App_release_data_time = GetValue(line)
		}
		if checkLineStartWith(line, util.PkgDtlAppType) {
			m.App_type = GetValue(line)
		}
		if checkLineStartWith(line, util.PkgDtlAppName) {
			m.App_product_name = GetValue(line)
		}
		if checkLineStartWith(line, util.PkgDtlAppId) {
			m.App_provider_id = GetValue(line)
		}
	}
}


func GetValue(line string) string {
	return strings.Trim(strings.Split(line, ":")[1]," ")
}

func checkLineStartWith(line string, s string) bool {
	res := false
	res = strings.HasPrefix(line, s)
	return res
}

// get file with extension
func (c *LcmControllerV2) GetFileContainsExtension(pkgDir string, ext string) (string, error) {
	data, err := os.Open(pkgDir)
	if err != nil {
		log.Error(util.FailedToFindAppPackage)
		return "", errors.New(util.FailedToFindAppPackage)
	}
	defer data.Close()

	files, err := data.Readdir(-1)
	if err != nil {
		log.Error(util.FailedToReadAppPackage)
		return "", errors.New(util.FailedToReadAppPackage)
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
func (c *LcmControllerV2) GetInputParametersForUploadCfg(clientIp string) (hostIp string,
	vim string, file multipart.File, err error) {
	hostIp, err = c.GetHostIP(clientIp)
	if err != nil {
		return hostIp, vim, file, err
	}

	vim, err = c.GetVim(clientIp, hostIp)
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

	err = c.ValidateYamlFile(clientIp, file)
	if err != nil {
		return hostIp, vim, file, err
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, err.Error(), util.ErrCodeFailedToSaveFile)
		return hostIp, vim, file, err
	}
	return hostIp, vim, file, nil
}

// Validate kubeconfig file
func (c *LcmControllerV2) ValidateYamlFile(clientIp string, file multipart.File) error {

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
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	_, err = c.IsPermitted(accessToken, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	hostIp, vim, hostInfoRec, tenantId, err := c.GetInputParametersForRemoveCfg(clientIp)
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
	_, err = adapter.RemoveConfig(hostIp, accessToken, tenantId)
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


func (c *LcmControllerV2) TenantIdAndVim(hostIp string, clientIp string) (string, string, error) {
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
	configTenantId := mecHostInfoRec.TenantId
	return vim, configTenantId, nil
}

// Get vim name
func (c *LcmControllerV2) GetVim(clientIp string, hostIp string) (string, error) {

	mecHostInfoRec, err := c.GetMecHostInfoRecord(hostIp, clientIp)
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
func (c *LcmControllerV2) GetInputParametersForRemoveCfg(clientIp string) (string, string, *models.MecHost, string, error) {
	hostIp, err := c.GetHostIP(clientIp)
	if err != nil {
		return "", "", &models.MecHost{}, "", err
	}


	hostInfoRec := &models.MecHost{
		MecHostId: hostIp,
	}

	readErr := c.Db.ReadData(hostInfoRec, util.HostIp)
	if readErr != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound,
			util.MecHostRecDoesNotExist, util.ErrCodeHostNotExist)
		return "", "", hostInfoRec, "", err
	}

	vim, configTenantId, err := c.TenantIdAndVim(clientIp, hostIp)
	if err != nil {
		return "", "", hostInfoRec, "", err
	}

	return hostIp, vim, hostInfoRec, configTenantId, err
}

// Get host IP
func (c *LcmControllerV2) GetHostIP(clientIp string) (string, error) {
	hostIp := c.GetString("hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.HostIpIsInvalid, util.ErrCodeMecHostInvalid)
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
	appInsId, tenantId, hostIp, packageId, appName, err := c.ValidateToken(accessToken, req, clientIp)
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
		MecHost:       hostIp,
		TenantId:      tenantId,
		AppPackageId:  packageId,
		AppName:       appName,
		ClientIP:      clientIp,
		AccessToken:   accessToken,
	}

	DoPrepareParams(c, appParams, bKey)
	DoInstantiate(c, appParams, bKey, req)
}

func DoPrepareParams(c *LcmControllerV2, params *models.AppInfoParams, bKey []byte) {
	appPkgHostRecord := &models.AppPackageHostRecord{
		AppPkgId: params.AppPackageId,
		HostIp: params.MecHost,
	}

	readErr := c.Db.ReadData(appPkgHostRecord, "app_package_id", "mec_host")
	if readErr != nil {
		c.HandleForErrorCode(params.ClientIP, util.StatusNotFound,
			"App package host record not exists", util.ErrCodeNotFoundInDB)
		util.ClearByteArray(bKey)
		return
	}
	if appPkgHostRecord.Status != "Distributed" && appPkgHostRecord.Status != "uploaded"{
		c.HandleForErrorCode(params.ClientIP, util.BadRequest,
			"application package distribution status is:"+appPkgHostRecord.Status, util.ErrCodePackDistributed)
		util.ClearByteArray(bKey)
		return
	}

	appInfoRecord := &models.AppInfoRecord{
		AppInstanceId: params.AppInstanceId,
	}

	readErr = c.Db.ReadData(appInfoRecord, util.AppInsId)
	if readErr == nil {
		c.HandleForErrorCode(params.ClientIP, util.BadRequest,
			"App instance info record already exists", util.ErrCodeInstanceIsExist)
		util.ClearByteArray(bKey)
		return
	}

}

func DoInstantiate(c *LcmControllerV2, params *models.AppInfoParams, bKey []byte, req models.InstantiateRequest) {
	vim, configTenantId, err := c.TenantIdAndVim(params.ClientIP, params.MecHost)
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
	err, acm := ProcessAkSkConfig(params.AppInstanceId, params.AppName, &req, params.ClientIP, params.TenantId)
	if err != nil {
		c.HandleForErrorCode(params.ClientIP, util.StatusInternalServerError, err.Error(), util.ErrCodeProcessAkSkFailed)
		util.ClearByteArray(bKey)
		return
	}

	err = c.InsertOrUpdateTenantRecord(params.ClientIP, params.TenantId)
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

	err = c.InsertOrUpdateAppInfoRecord(params.ClientIP, appInfoParams)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	err, status := adapter.Instantiate(configTenantId, params.AccessToken, params.AppInstanceId, req)
	util.ClearByteArray(bKey)
	if err != nil {
		c.HandleErrorForInstantiateApp(acm, params.ClientIP, params.AppInstanceId, params.TenantId)
		c.HandleForErrorCode(params.ClientIP, util.StatusInternalServerError, err.Error(), util.ErrCodePluginReportFailed)
		return
	}
	if status == util.Failure {
		c.HandleErrorForInstantiateApp(acm, params.ClientIP, params.AppInstanceId, params.TenantId)
		c.HandleForErrorCode(params.ClientIP, util.StatusInternalServerError, util.FailedToInstantiate,
			util.ErrCodePluginInstFailed)
		err = errors.New(util.FailedToInstantiate)
		return
	}
	c.handleLoggingForSuccess(nil, params.ClientIP, "Application instantiated successfully")
}

func (c *LcmControllerV2) ValidateToken(accessToken string, req models.InstantiateRequest, clientIp string) (string, string, string, string, string, error) {

	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.RequestBodyTooLarge, util.ErrCodeBodyTooLarge)
		return "", "", "", "", "", errors.New(util.RequestBodyTooLarge)
	}

	appInsId, tenantId, hostIp, packageId, appName, err := c.ValidateInstantiateInputParameters(clientIp, req)
	if err != nil {
		return "", "", "", "", "", err
	}
	name, err := c.GetUserName(clientIp)
	if err != nil {
		return "", "", "", "", "", err
	}

	key, err := c.GetKey(clientIp)
	if err != nil {
		return "", "", "", "", "", err
	}
	if accessToken != "" {
		err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, tenantId)
		if err != nil {
			c.HandleLoggingForTokenFailure(clientIp, err.Error())
			return "", "", "", "", "", err
		}
	} else {
		if name != "" && key != "" {
			err := c.validateCredentials(clientIp, name, key)
			if err != nil {
				return "", "", "", "", "", err
			}
		}
	}
	return appInsId, tenantId, hostIp, packageId, appName, nil
}

func (c *LcmControllerV2) ValidateInstantiateInputParameters(clientIp string, req models.InstantiateRequest) (string, string, string, string, string, error) {

	hostIp := req.HostIp
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.HostIpIsInvalid, util.ErrCodeMecHostInvalid)
		return "", "", "", "", "", err
	}

	packageId := req.PackageId
	if len(packageId) == 0 {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.PackageIdIsInvalid, util.ErrCodePackageIdInvalid)
		return "", "", "", "", "", err
	}

	if len(packageId) > 64 {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.PackageIdIsInvalid, util.ErrCodePackageIdInvalid)
		return "", "", "", "", "", errors.New("package id length exceeds max limit")
	}

	appName := req.AppName
	name, err := util.ValidateName(appName, util.NameRegex)
	if err != nil || !name {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.AppNameIsNotValid, util.ErrCodeAppNameInvalid)
		return "", "", "", "", "", errors.New(util.AppNameIsNotValid)
	}

	appInsId, err := c.GetAppInstId(clientIp)
	if err != nil {
		return "", "", "", "", "", err
	}

	tenantId, err := c.GetTenantId(clientIp)
	if err != nil {
		return "", "", "", "", "", err
	}

	return appInsId, tenantId, hostIp, packageId, appName, nil
}


// Insert or update application info record
func (c *LcmControllerV2) InsertOrUpdateAppInfoRecord(clientIp string, appInfoParams models.AppInfoRecord) error {
	origin := appInfoParams.Origin
	if origin == "" {
		origin = "MEO"
	}
	hostInfoRec := &models.MecHost{
		MecHostId: appInfoParams.MecHost,
	}

	readErr := c.Db.ReadData(hostInfoRec, util.HostIp)
	if readErr != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound,
			util.MecHostRecDoesNotExist, util.ErrCodeNotFoundInDB)
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
		MecHostRec:   hostInfoRec,
	}

	count, err := c.Db.QueryCountForTable("app_info_record", util.TenantId, appInfoParams.TenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeReportByDB)
		return err
	}

	if count >= util.MaxNumberOfRecords {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PackageNumUpToMax,
			util.ErrCodePackNumUptoMax)
		return errors.New("maximum number of app package records are exceeded for given tenant")
	}

	err = c.Db.InsertOrUpdateData(appInfoRecord, util.AppInsId)
	if err != nil && err.Error() != util.LastInsertIdNotSupported {
		log.Error("Failed to save app info record to database.")
		return err
	}
	return nil
}


// Insert or update tenant info record
func (c *LcmControllerV2) InsertOrUpdateTenantRecord(clientIp, tenantId string) error {
	tenantRecord := &models.TenantInfoRecord{
		TenantId: tenantId,
	}

	count, err := c.Db.QueryCount("tenant_info_record")
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeReportByDB)
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
func (c *LcmControllerV2) InsertOrUpdateAppPkgRecord(appId, clientIp, tenantId,
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
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeNotFoundInDB)
		return err
	}

	if count >= util.MaxNumberOfRecords {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PackageNumUpToMax,
			util.ErrCodePackNumUptoMax)
		return errors.New("maximum number of app package records are exceeded for given tenant")
	}
	err = c.Db.InsertOrUpdateData(appPkgRecord, util.AppPkgId)
	if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
		log.Error("Failed to save app package record to database.")
		return err
	}
	return nil
}

func (c *LcmControllerV2) HandleErrorForInstantiateApp(acm config.AppConfigAdapter,
	clientIp, appInsId, tenantId string) {
	err := acm.DeleteAppAuthConfig(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteAuthCfgFail)
		return
	}
	err = c.DeleteAppInfoRecord(appInsId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteDataFailed)
		return
	}

	err = c.DeleteTenantRecord(clientIp, tenantId)
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

	tenantId, err := c.IsPermitted(accessToken, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appInsId, err := c.GetAppInstId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appInfoRecord, err := c.GetAppInfoRecord(appInsId, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	vim, configTenantId, err := c.TenantIdAndVim(clientIp, appInfoRecord.MecHost)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.GetPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	_, err = adapter.Terminate(appInfoRecord.MecHost, accessToken, appInfoRecord.AppInstanceId, configTenantId)
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

	err = c.DeleteAppInfoRecord(appInsId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteDataFailed)
		return
	}

	err = c.DeleteTenantRecord(clientIp, tenantId)
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
}


// Get app Instance Id
func (c *LcmControllerV2) GetAppInstId(clientIp string) (string, error) {
	appInsId := c.Ctx.Input.Param(":appInstanceId")
	err := util.ValidateUUID(appInsId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, "App instance is invalid", util.ErrCodeInstanceIdInvalid)
		return "", err
	}
	return appInsId, nil
}

// Handle logging
func (c *LcmControllerV2) HandleLoggingForFailure(clientIp string, errorString string) {
	if strings.Contains(errorString, util.Forbidden) {
		c.HandleForErrorCode(clientIp, util.StatusForbidden, util.Forbidden, util.ErrCodeForbidden)
	} else if strings.Contains(errorString, util.AccessTokenIsInvalid) {
		c.HandleForErrorCode(clientIp, util.StatusUnauthorized, util.AuthorizationFailed, util.ErrCodeTokenInvalid)
	} else {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, errorString, util.ErrCodeInternalServer)
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

	_, err = c.isPermitted([]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole}, accessToken, clientIp)
	if err != nil {
		return
	}

	appInsId, err := c.GetAppInstId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appInfoRecord, err := c.GetAppInfoRecord(appInsId, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	vim, configTenantId, err := c.TenantIdAndVim(clientIp, appInfoRecord.MecHost)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.GetPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	response, err := adapter.Query(accessToken, appInsId, appInfoRecord.MecHost, configTenantId)
	util.ClearByteArray(bKey)
	if err != nil {
		res := strings.Contains(err.Error(), "not found")
		if res {
			c.HandleForErrorCode(clientIp, util.StatusNotFound, err.Error(), util.ErrCodeHostNotFoundInPlg)
			return
		}
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrorReportByPlugin)
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeInternalServer)
		return
	}
	c.handleLoggingForSuccessV1(clientIp, "Query workload statistics is successful")
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
	clientIp, bKey, accessToken, err := c.GetClientIpNew()
	if err != nil {
		return
	}
	hostIp, err := c.getUrlHostIP(clientIp)
	if err != nil {
		return
	}

	log.Info("host ip is: " + hostIp)
	vim, configTenantId, err := c.TenantIdAndVim(clientIp, hostIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.GetPluginAdapter("", clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	response, err := adapter.QueryKPI(accessToken, hostIp, configTenantId)
	util.ClearByteArray(bKey)
	c.HandleKPI(clientIp, err, response)
}

func (c *LcmControllerV2) GetClientIpNew() (clientIp string, bKey []byte,
	accessToken string, err error) {
	clientIp = c.Ctx.Input.IP()
	err = util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	accessToken = c.Ctx.Request.Header.Get(util.AccessToken)
	bKey = *(*[]byte)(unsafe.Pointer(&accessToken))
	tenantId, err := c.GetTenantId(clientIp)
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
	return clientIp, bKey, accessToken, err
}

func (c *LcmControllerV2) HandleKPI(clientIp string, err error, response string) {
	if err != nil {
		res := strings.Contains(err.Error(), util.NotFound)
		if res {
			c.HandleForErrorCode(clientIp, util.StatusNotFound, err.Error(), util.ErrCodePluginNotFound)
			return
		}
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(),util.ErrCodePluginReportFailed)
		return
	} else {
		_, err = c.Ctx.ResponseWriter.Write([]byte(response))
		if err != nil {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeInternalServer)
			return
		}
		c.handleLoggingForSuccessV1(clientIp, "Query kpi is successful")
	}
}

// Get host IP from url
func (c *LcmControllerV2) GetUrlHostIP(clientIp string) (string, error) {
	hostIp := c.Ctx.Input.Param(":hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, "MecHost address is invalid from url",
			util.ErrCodeMecHostInvalid)
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
	clientIp, bKey, _, err := c.GetClientIpNew()
	util.ClearByteArray(bKey)

	_, err = c.GetUrlHostIP(clientIp)
	if err != nil {
		return
	}

	mepPort := util.GetMepPort()

	capabilityId, err := c.GetUrlCapabilityId(clientIp)
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
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeInternalServer)
		return
	}
	c.handleLoggingForSuccessV1(clientIp, "Query mep capabilities is successful")
}

// Get mep capability id from url
func (c *LcmControllerV2) GetUrlCapabilityId(clientIp string) (string, error) {
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
	_, err = c.isPermitted([]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole}, accessToken, clientIp)
	if err != nil {
		return
	}

	appInsId, err := c.GetAppInstId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	appInfoRecord, err := c.GetAppInfoRecord(appInsId, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	vim, configTenantId, err := c.TenantIdAndVim(clientIp, appInfoRecord.MecHost)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	adapter, err := c.GetPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}
	response, err := adapter.GetWorkloadDescription(accessToken, appInfoRecord.MecHost, appInsId,
		configTenantId)
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
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeInternalServer)
		return
	}
	c.handleLoggingForSuccessV1(clientIp, "Workload description is successful")
}

// @Title Sync app instances stale records
// @Description Sync app instances stale records
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/sync_deleted [get]
func (c *LcmControllerV2) SynchronizeStaleRecord() {
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

	tenantId, err := c.GetTenantId(clientIp)
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


	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)

	for _, appInstStaleRec := range appInstStaleRecs {
		err = c.Db.DeleteData(&appInstStaleRec, util.AppInsId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteDataFailed)
			return
		}
	}
	c.handleLoggingForSuccess(appInstanceStaleRecords, clientIp, "Stale appInstance records synchronization is successful")
}

// @Title Sync app instances records
// @Description Sync app instances records
// @Param   tenantId    path 	string	    true   "tenantId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/sync_updated [get]
func (c *LcmControllerV2) SynchronizeUpdatedRecord() {
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

	tenantId, err := c.GetTenantId(clientIp)
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
		c.HandleForErrorCode(clientIp, util.BadRequest, util.FailedToMarshal, util.ErrCodeFailedToMarshal)
		return
	}
	err = json.Unmarshal(res, &appInstanceRes)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.FailedToUnmarshal, util.ErrCodeFailedToUnMarshal)
		return
	}

	appInstanceSyncRecords.AppInfoUpdatedRecs = append(appInstanceSyncRecords.AppInfoUpdatedRecs, appInstanceRes...)

	res, err = json.Marshal(appInstanceSyncRecords)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.FailedToMarshal, util.ErrCodeFailedToMarshal)
		return
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)


	for _, appInstance := range appInstancesSync {
		appInstance.SyncStatus = true
		err = c.Db.InsertOrUpdateData(&appInstance, util.AppInsId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			log.Error("Failed to save app info record to database.")
			return
		}
	}
	c.handleLoggingForSuccess(appInstanceSyncRecords, clientIp, "AppInstance synchronization is successful")
}

// @Title Delete package
// @Description Delete package
// @Param	tenantId	path 	string	true   "tenantId"
// @Param	packageId   path 	string	true   "packageId"
// @Param   access_token header  string true   "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/packages/:packageId [delete]
func (c *LcmControllerV2) DeletePackage() {
	clientIp, bKey, accessToken, err := c.GetClientIpAndValidateAccessToken("Delete application package request received.", []string{util.MecmTenantRole, util.MecmAdminRole}, "")
	defer util.ClearByteArray(bKey)
	if err != nil {
		return
	}

	tenantId, err := c.GetTenantId(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, err.Error(), util.ErrCodeTenantIdInvalid)
		return
	}

	packageId, err := c.GetUrlPackageId(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, err.Error(), util.ErrCodePackageIdInvalid)
		return
	}

	err = c.ProcessDeletePackage(clientIp, packageId, tenantId, accessToken)
	if err != nil {
		return
	}

	pkgFilePath := PackageFolderPath + tenantId + "/" + packageId + "/" + packageId + ".csar"
	err = c.deletePackageFromDir(path.Dir(pkgFilePath))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteFileFailed)
		return
	}

	err = c.DeleteAppPkgRecords(packageId, tenantId, clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteDataFailed)
		return
	}

	c.handleLoggingForSuccess(nil, clientIp, "Deleted application package successfully")
}

func (c *LcmControllerV2) GetClientIpAndValidateAccessToken(receiveMsg string, allowedRoles []string, tenantId string) (clientIp string, bKey []byte,
	accessToken string, err error) {
	log.Info(receiveMsg)
	clientIp = c.Ctx.Input.IP()
	err = util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
		return clientIp, bKey, accessToken, err
	}
	c.displayReceivedMsg(clientIp)
	name, key, err := c.GetUserNameAndKey(clientIp)
	if err != nil {
		return clientIp, bKey, accessToken, err
	}
	accessToken = c.Ctx.Request.Header.Get(util.AccessToken)
	if accessToken != "" {
		err = util.ValidateAccessToken(accessToken, allowedRoles, tenantId)
		if err != nil {
			c.HandleLoggingForTokenFailure(clientIp, err.Error())
			return clientIp, bKey, accessToken, err
		}
	} else {
		if name != "" && key != "" {
			err = c.validateCredentials(clientIp, name, key)
			if err != nil {
				return
			}
		}
	}
	bKey = *(*[]byte)(unsafe.Pointer(&accessToken))
	return clientIp, bKey, accessToken, nil
}

// Process delete packages
func (c *LcmControllerV2) ProcessDeletePackage(clientIp, packageId, tenantId, accessToken string) error {
	var appPkgRecords []*models.AppPackageRecord
	_, _ = c.Db.QueryTable(util.AppPackageRecordId, &appPkgRecords, util.AppPkgId, packageId+tenantId)

	for _, appPkgRecord := range appPkgRecords {
		_, _ = c.Db.LoadRelated(appPkgRecord, util.MecHostInfo)
	}

	for _, appPkgRecord := range appPkgRecords {
		for _, appPkgHost := range appPkgRecord.MecHostInfo {
			err := c.DeletePkg(appPkgHost, clientIp, packageId, accessToken)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Delete application package records
func (c *LcmControllerV2) DeleteAppPkgRecords(packageId, tenantId, clientIp string) error {
	appPkgRec := &models.AppPackageRecord{
		AppPkgId: packageId + tenantId,
	}

	err := c.Db.ReadData(appPkgRec, util.AppPkgId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound, util.RecordDoesNotExist, util.ErrCodeRecordNotExist)
		return err
	}
	var origin = appPkgRec.Origin

	err = c.DeleteAppPackageRecord(packageId, tenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteDataFailed)
		return err
	}

	err = c.DeleteTenantRecord(clientIp, tenantId)
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
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeInsertDataFailed)
			return err
		}
	}
	return nil
}

// Send delete package
func (c *LcmControllerV2) DeletePkg(appPkgHost *models.AppPackageHostRecord,
	clientIp, packageId, accessToken string) error {
	vim, configTenantId, err := c.TenantIdAndVim(clientIp, appPkgHost.HostIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeGetVimFailed)
		return err
	}

	pluginInfo := util.GetPluginInfo(vim)
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeFailedGetPlugin)
		return err
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.DeletePackage(configTenantId, appPkgHost.HostIp, packageId, accessToken)
	if err != nil {
		c.HandleLoggingForFailure(clientIp, err.Error())
		return err
	}
	return nil
}

func (c *LcmControllerV2) deletePackageFromDir(appPkgPath string) error {

	tenantPath := path.Dir(appPkgPath)

	//remove package directory
	err := os.RemoveAll(appPkgPath)
	if err != nil {
		log.Error("failed to delete application package file")
		return errors.New("failed to delete application package file")
	}

	tenantDir, err := os.Open(tenantPath)
	if err != nil {
		log.Error("failed to open tenant file")
		return errors.New("failed to open tenant file")
	}
	defer tenantDir.Close()

	_, err = tenantDir.Readdir(1)

	if err == io.EOF {
		err := os.Remove(tenantPath)
		if err != nil {
			log.Error("failed to remove tenant directory")
			return errors.New("failed to remove tenant directory")
		}
		return nil
	}
	return nil
}

// @Title Delete application package on host
// @Description Delete Package
// @Param   access_token  header     string true   "access token"
// @Param   packageId     header     string true   "package ID"
// @Param   hostIp        header     string true   "host IP"
// @Success 200 ok
// @Failure 400 bad request
// @router /packages/:packageId/hosts/:hostIp [delete]
func (c *LcmControllerV2) DeletePackageOnHost() {

	clientIp, bKey, accessToken, err := c.GetClientIpAndValidateAccessToken("Delete application package on host request received.", []string{util.MecmTenantRole, util.MecmAdminRole}, "")
	defer util.ClearByteArray(bKey)
	if err != nil {
		return
	}

	tenantId, packageId, hostIp, err := c.GetInputParametersForDelPkgOnHost(clientIp)
	if err != nil {
		return
	}

	pkgRecHostIp, configTenantId, vim, err := c.GetVimAndHostIpFromPkgHostRec(clientIp, packageId, tenantId, hostIp)
	if err != nil {
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
	_, err = adapter.DeletePackage(configTenantId, pkgRecHostIp, packageId, accessToken)
	if err != nil {
		c.HandleLoggingForFailure(clientIp, err.Error())
		return
	}
	err = c.DelAppPkgRecords(clientIp, packageId, configTenantId, hostIp)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(nil, clientIp, "Deleted host application package successfully")
}

// Get input parameters for delete package on host
func (c *LcmControllerV2) GetInputParametersForDelPkgOnHost(clientIp string) (string, string, string, error) {
	tenantId, err := c.GetTenantId(clientIp)
	if err != nil {
		return "", "", "", err
	}

	packageId, err := c.GetUrlPackageId(clientIp)
	if err != nil {
		return "", "", "", err
	}

	hostIp, err := c.GetUrlHostIP(clientIp)
	if err != nil {
		return "", "", "", err
	}

	return tenantId, packageId, hostIp, nil
}

// Get vim and host ip from package host record
func (c *LcmControllerV2) GetVimAndHostIpFromPkgHostRec(clientIp, packageId, tenantId, hostIp string) (string, string,
	string, error) {
	appPkgRecord, err := c.GetAppPackageRecord(packageId, tenantId, clientIp)
	if err != nil {
		return "", "", "", err
	}

	appPkgHostRecord, err := c.GetAppPackageHostRecord(hostIp, appPkgRecord.PackageId, appPkgRecord.TenantId, clientIp)
	if err != nil {
		return "", "", "", err
	}

	vim, configTenantId, err := c.TenantIdAndVim(clientIp, appPkgHostRecord.HostIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeGetVimFailed)
		return "", "", "", err
	}
	return appPkgHostRecord.HostIp, configTenantId, vim, err
}

// Get app package host record
func (c *LcmControllerV2) GetAppPackageHostRecord(hostIp, appPkgId, tenantId, clientIp string) (*models.AppPackageHostRecord, error) {
	appPkgHostRecord := &models.AppPackageHostRecord{
		PkgHostKey: appPkgId + tenantId + hostIp,
	}

	readErr := c.Db.ReadData(appPkgHostRecord, util.PkgHostKey)
	if readErr != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound,
			"App package host record does not exist in database", util.ErrCodeRecordNotExist)
		return nil, readErr
	}
	return appPkgHostRecord, nil
}

// Update app package records
func (c *LcmControllerV2) UpdateAppPkgRecord(hosts models.DistributeRequest,
	clientIp, tenantId, packageId, hostIp, status string) error {
	err := c.InsertOrUpdateTenantRecord(clientIp, tenantId)
	if err != nil {
		return err
	}

	err = c.InsertOrUpdateAppPkgHostRecord(hostIp, clientIp, tenantId, packageId,
		status, hosts.Origin)
	if err != nil {
		return err
	}
	return nil
}

// Insert or update application package host record
func (c *LcmControllerV2) InsertOrUpdateAppPkgHostRecord(hostIp, clientIp, tenantId,
	packageId, distributionStatus, origin string) error {

	if origin == "" {
		origin = "MECM"
	}

	originVar, err := util.ValidateName(origin, util.NameRegex)
	if err != nil || !originVar {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.OriginIsInvalid, util.ErrCodeOriginInvalid)
		return err
	}
	appPkgRec := &models.AppPackageRecord{
		AppPkgId: packageId + tenantId,
	}

	readErr := c.Db.ReadData(appPkgRec, util.AppPkgId)
	if readErr != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound, util.RecordDoesNotExist, util.ErrCodeRecordNotExist)
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
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeReportByDB)
		return err
	}

	if count >= util.MaxNumberOfRecords {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError,
			util.PackageNumUpToMax, util.ErrCodePackNumUptoMax)
		return errors.New("maximum number of app package host records are exceeded for given tenant")
	}

	err = c.Db.InsertOrUpdateData(appPkgHostRecord, util.PkgHostKey)
	if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
		log.Error("Failed to save app package host record to database.")
		return err
	}
	return nil
}

// Get input parameters for distribution status
func (c *LcmControllerV2) GetInputParametersForDistributionStatus(clientIp string) (string, string, error) {
	tenantId, err := c.GetTenantId(clientIp)
	if err != nil {
		return "", "", err
	}

	packageId, err := c.GetUrlPackageId(clientIp)
	if err != nil {
		return "", "", err
	}
	return tenantId, packageId, err
}

// Delete application pacakge records
func (c *LcmControllerV2) DelAppPkgRecords(clientIp, packageId, tenantId, hostIp string) error {
	appPkgHostRec := &models.AppPackageHostRecord{
		PkgHostKey: packageId + tenantId + hostIp,
	}

	err := c.Db.ReadData(appPkgHostRec, util.PkgHostKey)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound,
			util.RecordDoesNotExist, util.ErrCodeRecordNotExist)
		return err
	}
	var origin = appPkgHostRec.Origin

	err = c.DeleteAppPackageHostRecord(hostIp, packageId, tenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeReportByDB)
		return err
	}

	err = c.DeleteTenantRecord(clientIp, tenantId)
	if err != nil {
		return err
	}

	appPackageHostStaleRec := &models.AppPackageHostStaleRec{
		PackageId: packageId,
		TenantId:  tenantId,
		HostIp:    hostIp,
	}

	if strings.EqualFold(origin, "mepm") {
		err = c.Db.InsertOrUpdateData(appPackageHostStaleRec, util.PkgId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeReportByDB)
			return err
		}
	}
	return nil
}

// @Title Distribute package
// @Description Distribute Package
// @Param   access_token  header     string true   "access token"
// @Param   packageId     header     string true   "package ID"
// @Param   hostIp        body       string true   "host IP"
// @Success 200 ok
// @Failure 400 bad request
// @router /packages/:packageId [post]
func (c *LcmControllerV2) DistributePackage() {
	clientIp, bKey, accessToken, _, err := c.GetClientIpAndIsPermitted("Distribute application package request received.")
	defer util.ClearByteArray(bKey)
	if err != nil {
		return
	}

	var hosts models.DistributeRequest
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &hosts)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, err.Error(), util.ErrCodeFailedToUnMarshal)
		return
	}

	packageId, err := c.ValidateDistributeInputParameters(clientIp, hosts)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest,
			"invalid input parameters", util.ErrCodeBadRequest)
		return
	}

	tenantId, err := c.GetTenantId(clientIp)
	if err != nil {
		return
	}

	appPkgRecord := &models.AppPackageRecord{
		PackageId: packageId,
	}

	readErr := c.Db.ReadData(appPkgRecord, "package_id")
	if readErr != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound,
			"App package does not exist", util.ErrCodeRecordNotExist)
		return
	}

	err = c.ProcessUploadPackage(hosts, clientIp, tenantId, packageId, accessToken)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(nil, clientIp, "Distributed application package successfully")
}

func (c *LcmControllerV2) ValidateDistributeInputParameters(clientIp string, req models.DistributeRequest) (string, error) {

	for _, hostIp := range req.HostIp {
		err := util.ValidateIpv4Address(hostIp)
		if err != nil {
			return "", errors.New("invalid host IP")
		}
	}

	packageId, err := c.GetUrlPackageId(clientIp)
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

func (c *LcmControllerV2) GetClientIpAndIsPermitted(receiveMsg string) (clientIp string, bKey []byte,
	accessToken string, tenantId string, err error) {
	log.Info(receiveMsg)
	clientIp = c.Ctx.Input.IP()
	err = util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
		return clientIp, bKey, accessToken, tenantId, err
	}
	c.displayReceivedMsg(clientIp)
	accessToken = c.Ctx.Request.Header.Get(util.AccessToken)
	bKey = *(*[]byte)(unsafe.Pointer(&accessToken))
	tenantId, err = c.IsPermitted(accessToken, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return clientIp, bKey, accessToken, tenantId, err
	}
	return clientIp, bKey, accessToken, tenantId, nil
}

// Process the upload package
func (c *LcmControllerV2) ProcessUploadPackage(hosts models.DistributeRequest,
	clientIp, tenantId, packageId, accessToken string) error {
	for _, hostIp := range hosts.HostIp {

		vim, configTenantId, err := c.TenantIdAndVim(clientIp, hostIp)
		if err != nil {
			return err
		}
		pkgFilePath := PackageFolderPath + configTenantId + "/" + packageId + "/" + packageId + ".csar"
		pluginInfo := util.GetPluginInfo(vim)
		client, err := pluginAdapter.GetClient(pluginInfo)
		if err != nil {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToGetClient,
				util.ErrCodeFailedGetClient)
			return err
		}
		adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
		status, err := adapter.UploadPackage(configTenantId, pkgFilePath, hostIp, packageId, accessToken)
		if err != nil {
			c.HandleLoggingForFailure(clientIp, err.Error())
			err = c.UpdateAppPkgRecord(hosts, clientIp, tenantId, packageId, hostIp, "Error")
			return err
		}
		if status == util.Failure {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToUploadToPlugin,
				util.ErrCodeUploadToPluginFailed)
			err = errors.New(util.FailedToUploadToPlugin)
			return err
		}

		err = c.UpdateAppPkgRecord(hosts, clientIp, tenantId, packageId, hostIp, "Distributing")
		if err != nil {
			return err
		}
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
func (c *LcmControllerV2) DistributionStatus() {
	clientIp, bKey, accessToken, tenantId, err := c.GetClientIpAndIsPermitted("Distribute status request received.")
	defer util.ClearByteArray(bKey)
	if err != nil {
		return
	}

	_, packageId, err := c.GetInputParametersForDistributionStatus(clientIp)
	if err != nil {
		return
	}

	appPkgRecords, err := c.GetAppPkgRecords(clientIp, packageId, tenantId)
	if err != nil {
		return
	}

	appPkgs, err := c.GetAppPkgs(clientIp, accessToken, tenantId, appPkgRecords)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(appPkgs, clientIp, "Query app package records successful")
}

// @Title Sync app package records
// @Description Sync app package records
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/packages/sync_updated [get]
func (c *LcmControllerV2) SynchronizeAppPackageUpdatedRecord() {
	log.Info("Sync app package request received.")

	var appPackages []*models.AppPackageRecord
	var appPackagesSync []*models.AppPackageRecord

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.ClientIpaddressInvalid, util.ErrCodeIPInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))

	tenantId, err := c.GetTenantId(clientIp)
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

	err = c.SendAppPkgSyncRecords(appPackagesSync, clientIp)
	if err != nil {
		return
	}

	err = c.InsertAppPackageRec(appPackagesSync)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(nil, clientIp, "Application packages synchronization is successful")
}

// Insert app package records
func (c *LcmControllerV2) InsertAppPackageRec(appPackagesSync []*models.AppPackageRecord) error {
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
func (c *LcmControllerV2) SendAppPkgSyncRecords(appPackagesSync []*models.AppPackageRecord, clientIp string) error {
	var appPackageRec []models.AppPackageRecordInfo
	var appPackageSyncRecords models.AppPackagesUpdatedRecords

	res, err := json.Marshal(appPackagesSync)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.FailedToMarshal, util.ErrCodeFailedToMarshal)
		return err
	}
	err = json.Unmarshal(res, &appPackageRec)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.FailedToUnmarshal, util.ErrCodeFailedToUnMarshal)
		return err
	}

	appPackageSyncRecords.AppPackagesUpdatedRecs = append(appPackageSyncRecords.AppPackagesUpdatedRecs, appPackageRec...)

	response, err := json.Marshal(appPackageSyncRecords)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.FailedToMarshal, util.ErrCodeFailedToMarshal)
		return err
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)
	_, err = c.Ctx.ResponseWriter.Write(response)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeWriteResFailed)
		return err
	}
	return nil
}

// @Title Sync app package stale records
// @Description Sync mec host stale records
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/packages/sync_deleted [get]
func (c *LcmControllerV2) SynchronizeAppPackageStaleRecord() {
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

	tenantId, err := c.GetTenantId(clientIp)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.TenantIdIsInvalid, util.ErrCodeTenantIdInvalid)
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
		c.writeErrorResponse("failed to marshal request", util.BadRequest)
		return
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)
	_, err = c.Ctx.ResponseWriter.Write(res)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeWriteResFailed)
		return
	}
	for _, appPackageStaleRec := range appPackageStaleRecs {
		err = c.Db.DeleteData(&appPackageStaleRec, util.AppPkgId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteDataFailed)
			return
		}
	}

	for _, appPkgHostStaleRec := range appPkgHostStaleRecs {
		err = c.Db.DeleteData(&appPkgHostStaleRec, util.PkgId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleForErrorCode(clientIp, util.StatusInternalServerError, err.Error(), util.ErrCodeDeleteDataFailed)
			return
		}
	}

	c.handleLoggingForSuccess(nil, clientIp, "Stale app package records synchronization is successful")
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

func (c *BaseController) IsPermitted(accessToken, clientIp string) (string, error) {
	var tenantId = ""
	var err error

	if len(c.Ctx.Input.RequestBody) > util.RequestBodyLength {
		c.HandleForErrorCode(clientIp, util.BadRequest, util.RequestBodyTooLarge, util.ErrCodeBodyTooLarge)
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
		err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, tenantId)
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

func (c *LcmControllerV2) GetMecHostInfoRecord(hostIp string, clientIp string) (*models.MecHost, error) {

	mecHostInfoRecord := &models.MecHost{
		MechostIp: hostIp,
	}

	readErr := c.Db.ReadData(mecHostInfoRecord, util.MecHostIp)
	log.Info("host ip : " + mecHostInfoRecord.MecHostId)
	if readErr != nil {
		log.Info("Error is: ", readErr.Error())
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

func (c *LcmControllerV2) GetPluginAdapter(_, clientIp string, vim string) (*pluginAdapter.PluginAdapter,
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

func (c *LcmControllerV2) GetAppPkgRecords(clientIp, packageId, tenantId string) (appPkgRecords []*models.AppPackageRecord, err error) {
	edgeKey, _ := c.getKey(clientIp)
	if edgeKey != "" {
		count, _ := c.Db.QueryTable(util.AppPackageRecordId, &appPkgRecords, "")
		if count == 0 {
			c.HandleForErrorCode(clientIp, util.StatusNotFound, util.RecordDoesNotExist, util.ErrCodeRecordNotExist)
			return appPkgRecords, errors.New(util.RecordDoesNotExist)
		}
	} else {
		if packageId == ""  {
			count, _ := c.Db.QueryTable(util.AppPackageRecordId, &appPkgRecords, util.TenantId, tenantId)
			if count == 0 {
				c.HandleForErrorCode(clientIp, util.StatusNotFound, util.RecordDoesNotExist, util.ErrCodeRecordNotExist)
				return appPkgRecords, errors.New(util.RecordDoesNotExist)
			}
		} else {
			count, _ := c.Db.QueryTable(util.AppPackageRecordId, &appPkgRecords, util.AppPkgId, packageId + tenantId)
			if count == 0 {
				c.HandleForErrorCode(clientIp, util.StatusNotFound, util.RecordDoesNotExist, util.ErrCodeRecordNotExist)
				return appPkgRecords, errors.New(util.RecordDoesNotExist)
			}
		}
	}
	return appPkgRecords, nil
}

func (c *LcmControllerV2) GetAppPkgs(clientIp, accessToken, tenantId string,
	appPkgRecords []*models.AppPackageRecord) (appPkgs []models.AppPackageStatusRecord, err error) {
	var status string

	for _, appPkgRecord := range appPkgRecords {
		_, _ = c.Db.LoadRelated(appPkgRecord, util.MecHostInfo)
	}

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

			if appPkgHost.Status != "Distributed" {
				pluginInfo, client, err := c.GetPluginAndClient(clientIp, p.PackageId, tenantId, ph.HostIp)
				if err != nil {
					log.Error("Error happens then continue")
					continue
				}
				_, configTenantId, err := c.TenantIdAndVim(ph.HostIp, clientIp)
				adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
				status, err = adapter.QueryPackageStatus(configTenantId, ph.HostIp, p.PackageId, accessToken)
				if err != nil {
					c.HandleLoggingForFailure(clientIp, err.Error())
					continue
				}
				ph.Status = HandleStatus(status)
				appPkgHost.Status = ph.Status
				_ = c.Db.InsertOrUpdateData(appPkgHost, util.PkgHostKey)
			} else {
				ph.Status = appPkgHost.Status
			}
			ph.Error = appPkgHost.Error
			p.MecHostInfo = append(p.MecHostInfo, &ph)
		}
		appPkgs = append(appPkgs, p)
	}
	return appPkgs, nil
}



