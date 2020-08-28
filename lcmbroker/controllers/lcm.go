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
	"errors"
	"github.com/astaxie/beego"
	"github.com/buger/jsonparser"
	"github.com/ghodss/yaml"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"io/ioutil"
	"lcmbroker/models"
	"mime/multipart"
	"path/filepath"
	"strings"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"lcmbroker/pkg/handlers/pluginAdapter"
	"lcmbroker/util"
	"os"
)

var (
	PackageFolderPath   = "/usr/app/"
	PackageArtifactPath = "/Artifacts/Deployment/"
)

// Lcm Controller
type LcmController struct {
	beego.Controller
	db Database
}

// Upload Config
func (c *LcmController) UploadConfig() {
	log.Info("Add configuration request received.")
	clientIp := c.Ctx.Request.Header.Get(util.XRealIp)
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest,util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}

	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	file, header, err := c.GetFile("configFile")
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Upload config file error")
		return
	}

	err = util.ValidateFileSize(header.Size, util.MaxConfigFile)
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "File size is larger than max size")
		return
	}

	pluginInfo := util.HelmPlugin + ":" + os.Getenv(util.HelmPluginPort)

	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		return
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.UploadConfig(file, hostIp, accessToken)
	util.ClearByteArray(bKey)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Upload configuration failed")
		return
	}

	c.ServeJSON()
}

// Remove Config
func (c *LcmController) RemoveConfig() {
	log.Info("Delete configuration request received.")
	clientIp := c.Ctx.Request.Header.Get(util.XRealIp)
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest,util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	pluginInfo := util.HelmPlugin + ":" + os.Getenv(util.HelmPluginPort)

	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		return
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.RemoveConfig(hostIp, accessToken)
	util.ClearByteArray(bKey)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Remove configuration failed")
		return
	}
	c.ServeJSON()
}

// Instantiate application
func (c *LcmController) Instantiate() {
	log.Info("Application instantiation request received.")

	clientIp := c.Ctx.Request.Header.Get(util.XRealIp)
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest,util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}

	hostIp, appInsId, file, header, err := c.getInputParameters(clientIp)
	if err != nil {
		return
	}

	packageName := getPackageName(header)
	pkgPath := PackageFolderPath + header.Filename
	err = c.createPackagePath(pkgPath, clientIp, file)
	if err != nil {
		return
	}

	err = c.makeTargetDirectory(clientIp, packageName)
	if err != nil {
		return
	}

	c.openPackage(pkgPath)
	var yamlFile = PackageFolderPath + packageName + "/Definitions/" + "MainServiceTemplate.yaml"
	deployType := c.getApplicationDeploymentType(yamlFile)
	deployType = "helm"

	err = c.insertOrUpdateAppInfoRecord(appInsId, hostIp, deployType)
	if err != nil {
		return
	}

	artifact, pluginInfo, err := c.getArtifactAndPluginInfo(deployType, packageName, clientIp)
	if err != nil {
		return
	}
	err = c.InstantiateApplication(pluginInfo, hostIp, artifact, clientIp, accessToken, appInsId)
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	util.ClearByteArray(bKey)
	if err != nil {
		return
	}

	c.ServeJSON()
}

// Terminate application
func (c *LcmController) Terminate() {
	log.Info("Application termination request received.")
	var pluginInfo string

	clientIp := c.Ctx.Request.Header.Get(util.XRealIp)
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest,util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	accessToken := c.Ctx.Request.Header.Get(util.AccessToken)
	err = util.ValidateAccessToken(accessToken)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusUnauthorized, util.AuthorizationFailed)
		return
	}

	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
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

	switch appInfoRecord.DeployType {
	case "helm":
		pluginInfo = util.HelmPlugin + ":" + os.Getenv(util.HelmPluginPort)
	default:
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Deployment type is not helm based")
		return
	}

	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		return
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.Terminate(appInfoRecord.HostIp, accessToken, appInfoRecord.AppInsId)
	util.ClearByteArray(bKey)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Terminate application failed")
		return
	}
}

// Query
func (c *LcmController) Query() {
	log.Info("Application query request received.")
}

// Query KPI
func (c *LcmController) QueryKPI() {
	log.Info("Query KPI request received.")
}

// Query Mep capabilities
func (c *LcmController) QueryMepCapabilities() {
	log.Info("Query mep capabilities request received.")
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

// Decodes application descriptor
func (c *LcmController) getApplicationDeploymentType(serviceTemplate string) string {
	yamlFile, err := ioutil.ReadFile(serviceTemplate)
	if err != nil {
		c.writeResponse("Failed to read service template file", util.StatusInternalServerError)
	}

	jsonData, err := yaml.YAMLToJSON(yamlFile)
	if err != nil {
		c.writeResponse("Failed to parse yaml file", util.StatusInternalServerError)
	}

	deployType, _, _, _ := jsonparser.Get(jsonData, "topology_template", "node_templates", "face_recognition", "properties", "type")

	//return appPackageInfo
	return string(deployType)
}

// Opens package
func (c *LcmController) openPackage(packagePath string) {
	zipReader, _ := zip.OpenReader(packagePath)
	for _, file := range zipReader.Reader.File {

		zippedFile, err := file.Open()
		if err != nil || zippedFile == nil {
			c.writeErrorResponse("Failed to open zip file", util.StatusInternalServerError)
			continue
		}

		defer zippedFile.Close()

		isContinue := c.extractFiles(file, zippedFile)
		if isContinue {
			continue
		}
	}
}

// Extract files
func (c *LcmController) extractFiles(file *zip.File, zippedFile io.ReadCloser) bool {
	targetDir := PackageFolderPath + "/"
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
			return true
		}

		defer outputFile.Close()

		_, err = io.Copy(outputFile, zippedFile)
		if err != nil {
			c.writeErrorResponse("Failed to copy zipped file", util.StatusInternalServerError)
		}
	}
	return false
}

// Make target directory
func (c *LcmController) makeTargetDirectory(clientIp string, packageName string) error {
	err := os.Mkdir(PackageFolderPath + packageName, 0750)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Failed to create target directory")
		return err
	}
	return nil
}

// Instantiate application
func (c *LcmController) InstantiateApplication(pluginInfo string, hostIp string,
	artifact string, clientIp string, accessToken string, appInsId string) error {
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		return err
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	err, resStatus := adapter.Instantiate(hostIp, artifact, accessToken, appInsId)
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.InvalidArgument {
			c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.InstantiationFailed)
			return err
		} else {
			c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.InstantiationFailed)
		}
		return err
	}
	if resStatus == "Failure" {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.InstantiationFailed)
		return errors.New("instantiation failed")
	}
	return nil
}

// Get app info record
func (c *LcmController) getAppInfoRecord(appInsId string, clientIp string) (*models.AppInfoRecord, error) {
	appInfoRecord := &models.AppInfoRecord{
		AppInsId: appInsId,
	}
	c.initDbAdapter()
	readErr := c.db.ReadData(appInfoRecord, "app_ins_id")
	if readErr != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"App info record does not exist in database")
		return nil, readErr
	}
	return appInfoRecord, nil

}

// Get host IP
func (c *LcmController) getHostIP(clientIp string) (string, error) {
	hostIp := c.GetString("hostIp")
	err := util.ValidateIpv4Address(hostIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest,"HostIp address is invalid")
		return "", err
	}
	return hostIp, nil
}

// Get app Instance Id
func (c *LcmController) getAppInstId(clientIp string) (string, error) {
	appInsId := c.Ctx.Input.Param(":appInstanceId")
	err := util.ValidateUUID(appInsId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest,"App instance invalid")
		return "", err
	}
	return appInsId, nil
}

// Create package path
func (c *LcmController) createPackagePath(pkgPath string, clientIp string, file multipart.File) error {

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,"Failed to copy csar file")
		return err
	}

	newFile, err := os.Create(pkgPath)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,"Failed to create package path")
		return err
	}
	defer newFile.Close()
	if _, err := newFile.Write(buf.Bytes()); err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,"Failed to write csar file")
		return err
	}
	return nil
}

// Get package name
func getPackageName(header *multipart.FileHeader) string {
	var packageName = ""
	f := strings.Split(header.Filename, ".")
	if len(f) > 0 {
		packageName = f[0]
	}
	return packageName
}

// Get artifact and plugin info
func (c *LcmController) getArtifactAndPluginInfo(deployType string, packageName string,
	clientIp string) (string, string, error) {
	switch deployType {
	case "helm":
		pkgPath := PackageFolderPath + packageName + PackageArtifactPath + "Charts"
		artifact, err := c.getDeploymentArtifact(pkgPath, ".tar")
		if artifact == "" {
			c.handleLoggingForError(clientIp, util.StatusInternalServerError,
				"Artifact not available in application package.")
			return "", "", err
		}
		pluginInfo := util.HelmPlugin + ":" + os.Getenv(util.HelmPluginPort)
		return artifact, pluginInfo, nil
	default:
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Deployment type is not helm based")
		return "", "", errors.New("deployment type is not helm based")
	}
}

// Handled logging for error case
func (c *LcmController) handleLoggingForError(clientIp string, code int, errMsg string) {
	c.writeErrorResponse(errMsg, code)
	log.Info("Response message for ClientIP [" + clientIp + "] Operation [" + c.Ctx.Request.Method + "]" +
		" Resource [" + c.Ctx.Input.URL() + "] Result [Failure: " + errMsg + ".]")
	return
}

// Insert or update application info record
func (c *LcmController)insertOrUpdateAppInfoRecord(appInsId string, hostIp string, deployType string) error {
	appInfoRecord := &models.AppInfoRecord{
		AppInsId:   appInsId,
		HostIp:     hostIp,
		DeployType: deployType,
	}
	c.initDbAdapter()
	err := c.db.InsertOrUpdateData(appInfoRecord, "app_ins_id")
	if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
		log.Error("Failed to save app info record to database.")
		return err
	}
	return nil
}

// Get input parameters
func (c *LcmController) getInputParameters(clientIp string) (string, string, multipart.File,
	*multipart.FileHeader, error) {
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		return "", "", nil, nil, err
	}

	appInsId, err := c.getAppInstId(clientIp)
	if err != nil {
		return "", "", nil, nil, err
	}

	file, header, err := c.getFile(clientIp)
	if err != nil {
		return "", "", nil, nil, err
	}
	return hostIp, appInsId, file, header, nil
}

// Init Db adapter
func (c *LcmController) initDbAdapter() {
	dbAdapter := util.GetAppConfig("dbAdapter")
	switch dbAdapter {
	case "pgDb":
		if c.db == nil {
			pgDbadapter, err := NewPgDbAdapter()
			if err != nil {
				return
			}
			c.db = pgDbadapter
		}
		return
	default:
		return
	}
}

// To display log for received message
func (c *LcmController) displayReceivedMsg(clientIp string) {
	log.Info("Received message from ClientIP [" + clientIp + "] Operation [" + c.Ctx.Request.Method + "]" +
		" Resource [" + c.Ctx.Input.URL() + "]")
}
