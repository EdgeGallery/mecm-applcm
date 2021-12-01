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
	"archive/zip"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"lcmcontroller/config"
	"lcmcontroller/models"
	"path"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ghodss/yaml"
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

// extract CSAR package
func extractCsarPackage(packagePath string) (string, error) {
	zipReader, _ := zip.OpenReader(packagePath)
	if len(zipReader.File) > util.TooManyFile {
		return "", errors.New("Too many files contains in zip file")
	}
	defer zipReader.Close()
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

// Process Ak Sk configuration
func ProcessAkSkConfig(appInsId, appName string, req *models.InstantiateRequest, clientIp string,
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
		log.Error("failed to read app config file")
		return err, config.AppConfigAdapter{}
	}
	defer configYaml.Close()

	mfFileBytes, _ := ioutil.ReadAll(configYaml)

	data, err := yaml.YAMLToJSON(mfFileBytes)
	if err != nil {
		log.Error(util.FailedToCovertYamlToJson)
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
		log.Error("failed to read meta file")
		return "", err
	}
	defer mfYaml.Close()

	mfFileBytes, _ := ioutil.ReadAll(mfYaml)

	data, err := yaml.YAMLToJSON(mfFileBytes)
	if err != nil {
		log.Error(util.FailedToCovertYamlToJson)
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

	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)
	err = c.ValidateTokenAndCredentials(accessToken, clientIp, "")
	if err != nil {
		return
	}

	hostIp, err := c.GetUrlHostIP(clientIp)
	if err != nil {
		return
	}

	packageId, err := c.GetUrlPackageId(clientIp)
	if err != nil {
		return
	}

	appInfoRecord := &models.AppInfoRecord{
		MecHost:      hostIp,
		AppPackageId: packageId,
	}

	response := map[string]bool{"package_deployed": true}
	readErr := c.Db.ReadData(appInfoRecord, "app_package_id", "mec_host")
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

// Get new key
func (c *LcmController) GetNewKey(clientIp string) (string, error) {
	newKey := c.Ctx.Request.Header.Get("newkey")
	if newKey != "" {
		newKeyValid, err := util.ValidateDbParams(newKey)
		if err != nil || !newKeyValid {
			c.HandleLoggingForError(clientIp, util.BadRequest, "new key is invalid")
			return "", errors.New("new key is invalid")
		}
	}
	return newKey, nil
}

// Get host IP
func (c *LcmController) GetUrlHostIP(clientIp string) (string, error) {
	hostIp := c.Ctx.Input.Param(":hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.HostIpIsInvalid)
		return "", err
	}
	return hostIp, nil
}

// Get Package Id from url
func (c *LcmController) GetUrlPackageId(clientIp string) (string, error) {
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


func createDirectory(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return errors.New("failed to create directory")
		}
	}
	return nil
}

// @Title Change key
// @Description Change key
// @Param	name		 formData 	string	true   "name"
// @Param   key          formData   string  true   "key"
// @Param   newkey       formData   string  true   "newkey"
// @Success 200 ok
// @Failure 400 bad request
// @router /password [post]
func (c *LcmController) ChangeKey() {
	log.Info("Add change key request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	userName, key, newKey, err := c.GetInputParametersForChangeKey(clientIp)
	if err != nil {
		return
	}

	if userName != "" {
		edgeAuthInfoRec := &models.EdgeAuthenticateRec{
			Name: userName,
		}

		readErr := c.Db.ReadData(edgeAuthInfoRec, "name")
		if readErr != nil {
			c.HandleLoggingForError(clientIp, util.StatusNotFound,
				"Edge auth info record does not exist in database")
			return
		}

		if strings.Compare(key, edgeAuthInfoRec.Key) != 0 {
			c.HandleLoggingForError(clientIp, util.BadRequest,
				"Old password is not matched")
			return
		}

		edgeAuthInfoRec.Key = newKey
		err = c.Db.InsertOrUpdateData(edgeAuthInfoRec, "authenticate_id")
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleLoggingForError(clientIp, util.BadRequest,
				"Failed to save edge auth info record to database.")
			return
		}
	}
	c.handleLoggingForSuccess(clientIp, "Change key is successful")
	c.ServeJSON()
}


// @Title Login Page
// @Description Login Page
// @Param	name		 formData 	string	true   "name"
// @Param   key          formData   string  true   "key"
// @Success 200 ok
// @Failure 400 bad request
// @router /login [post]
func (c *LcmController) LoginPage() {
	log.Info("Add change key request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	userName, key, _, err := c.GetInputParametersForChangeKey(clientIp)
	if err != nil {
		return
	}

	if userName != "" {
		edgeAuthInfoRec := &models.EdgeAuthenticateRec{
			Name: userName,
		}

		readErr := c.Db.ReadData(edgeAuthInfoRec, "name")
		if readErr != nil {
			c.HandleLoggingForError(clientIp, util.StatusNotFound,
				"Edge auth info record does not exist in database")
			return
		}

		if strings.Compare(key, edgeAuthInfoRec.Key) != 0 {
			c.HandleLoggingForError(clientIp, util.BadRequest,
				"Invalid credentials")
			return
		}
		response, err := json.Marshal(edgeAuthInfoRec)
		if err != nil {
			c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
			return
		}
		_, _ = c.Ctx.ResponseWriter.Write(response)
	}
	c.handleLoggingForSuccess(clientIp, "Login Page is is successful")
}

// Get input parameters for upload configuration
func (c *LcmController) GetInputParametersForChangeKey(clientIp string) (name string,
	key string, newKey string, err error) {
	name, err = c.GetUserName(clientIp)
	if err != nil {
		return name, key, newKey, err
	}

	key, err = c.GetKey(clientIp)
	if err != nil {
		return name, key, newKey, err
	}

	newKey, err = c.GetNewKey(clientIp)
	if err != nil {
		return name, key, newKey, err
	}

	return name, key, newKey, nil
}

// @Title Profile application
// @Description Execute sh file of application
// @Param	tenantId	path 	string	true   "tenantId"
// @Param	appInstanceId   path 	string	true   "appInstanceId"
// @Param       access_token    header  string  true   "access token"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/:appInstanceId/terminate [post]
func (c *LcmController) Profile() {
	log.Info("Application profile execute request received.")

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

	packageId := appInfoRecord.AppPackageId
	pkgPath := PackageFolderPath + tenantId + "/" + packageId
	result, err := c.ExecuteFile(pkgPath)
	if err != nil {
		c.HandleLoggingForFailure(clientIp, err.Error())
		return
	}

	c.handleForNewSuccess(result, clientIp, "Script execute is successful")
}

func (c *LcmController) ExecuteFile(pkgPath string) (string, error) {
	pkgPath = pkgPath + "/Artifacts/Deployment/Scripts"
	files, err := ioutil.ReadDir(pkgPath)
	if err != nil {
		log.Error("failed to read directory")
		return "", nil
	}

	var shellPath string
	for _, filename := range files {
		if filepath.Ext(filename.Name()) == ".sh" {
			shellPath = filename.Name()
			break
		}
	}

	argv := make([]string, 1)
	attr := new(os.ProcAttr)
	newProcess, err := os.StartProcess(pkgPath + "/"+ shellPath, argv, attr)  //运行脚本
	if err != nil {
		log.Error("failed to execute script", err.Error())
	}
	processState, err := newProcess.Wait() //等待命令执行完
	if err != nil {
		log.Error("failed to execute script", err.Error())
	}
	return processState.String(), nil
}

func (c *LcmController) handleForNewSuccess(object interface{}, clientIp string, msg string) {
	log.Info("Response for ClientIP [" + clientIp + util.Operation + c.Ctx.Request.Method + "]" +
		util.Resource + c.Ctx.Input.URL() + "] Result [Success: " + msg + ".]")
	returnContent := handleSuccessReturn(object, msg)
	c.Data["json"] = returnContent
	c.Ctx.ResponseWriter.WriteHeader(util.SuccessCode)
	c.ServeJSON()
}


// Get app info record
func (c *BaseController) GetAppInfoRecord(appInsId string, clientIp string) (*models.AppInfoRecord, error) {
	appInfoRecord := &models.AppInfoRecord{
		AppInstanceId: appInsId,
	}

	readErr := c.Db.ReadData(appInfoRecord, util.AppInsId)
	if readErr != nil {
		c.HandleForErrorCode(clientIp, util.StatusNotFound,
			"App info record does not exist in database", util.ErrCodeNotFoundInDB)
		return nil, readErr
	}
	return appInfoRecord, nil
}
