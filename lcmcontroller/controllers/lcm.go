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
	"github.com/astaxie/beego"
	"github.com/buger/jsonparser"
	"github.com/ghodss/yaml"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"io/ioutil"
	"lcmcontroller/models"
	"lcmcontroller/pkg/dbAdapter"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"os"
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

// Upload Config
func (c *LcmController) UploadConfig() {
	log.Info("Add configuration request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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

	pluginInfo := os.Getenv(util.K8sPlugin) + ":" + os.Getenv(util.K8sPluginPort)

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
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Upload configuration failed")
		return
	}

	c.ServeJSON()
}

// Remove Config
func (c *LcmController) RemoveConfig() {
	log.Info("Delete configuration request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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

	pluginInfo := os.Getenv(util.K8sPlugin) + ":" + os.Getenv(util.K8sPluginPort)

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
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Remove configuration failed")
		return
	}
	c.ServeJSON()
}

// Instantiate application
func (c *LcmController) Instantiate() {
	log.Info("Application instantiation request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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
	hostIp, appInsId, file, header, tenantId, err := c.getInputParameters(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	packageName := getPackageName(header)
	pkgPath := PackageFolderPath + header.Filename
	err = c.createPackagePath(pkgPath, clientIp, file)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	err = c.makeTargetDirectory(clientIp, packageName)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	c.openPackage(pkgPath)
	var mainServiceTemplateMf = PackageFolderPath + packageName + "/MainServiceTemplate.mf"
	deployType, err := c.getApplicationDeploymentType(mainServiceTemplateMf)
	if err != nil {
		util.ClearByteArray(bKey)
		_ = removeCsarFiles(packageName, header)
		return
	}

	err = c.insertOrUpdateTenantRecord(clientIp, tenantId)
	if err != nil {
		util.ClearByteArray(bKey)
		_ = removeCsarFiles(packageName, header)
		return
	}
	err = c.insertOrUpdateAppInfoRecord(appInsId, hostIp, deployType, clientIp, tenantId)
	if err != nil {
		util.ClearByteArray(bKey)
		_ = removeCsarFiles(packageName, header)
		return
	}

	artifact, pluginInfo, err := c.getArtifactAndPluginInfo(deployType, packageName, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		_ = removeCsarFiles(packageName, header)
		return
	}
	err = c.InstantiateApplication(pluginInfo, hostIp, artifact, clientIp, accessToken, appInsId)
	util.ClearByteArray(bKey)
	if err != nil {
		_ = removeCsarFiles(packageName, header)
		return
	}
	err = removeCsarFiles(packageName, header)
	if err != nil {
		return
	}

	c.ServeJSON()
}

// Remove CSAR files
func removeCsarFiles(packageName string, header *multipart.FileHeader) error {
	err := os.RemoveAll(PackageFolderPath + packageName)
	if err != nil {
		log.Error("Failed to remove csar folder")
		return err
	}
	err = os.Remove(PackageFolderPath + header.Filename)
	if err != nil {
		log.Error("Failed to remove csar file")
		return err
	}
	return nil
}

// Terminate application
func (c *LcmController) Terminate() {
	log.Info("Application termination request received.")
	var pluginInfo string

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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
	tenantId, err := c.getTenantId(clientIp)
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

	switch appInfoRecord.DeployType {
	case "helm":
		pluginInfo = os.Getenv(util.K8sPlugin) + ":" + os.Getenv(util.K8sPluginPort)
	default:
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.DeployTypeIsNotHelmBased)
		return
	}

	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	_, err = adapter.Terminate(appInfoRecord.HostIp, accessToken, appInfoRecord.AppInsId)
	util.ClearByteArray(bKey)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Terminate application failed")
		return
	}
	err = c.deleteAppInfoRecord(appInsId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Failed to delete app info record")
		return
	}

	err = c.deleteTenantRecord(tenantId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Failed to delete tenant record")
		return
	}
	c.ServeJSON()
}

// Query
func (c *LcmController) Query() {
	log.Info("Application query request received.")
	var pluginInfo string

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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
	_, err = c.getTenantId(clientIp)
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

	switch appInfoRecord.DeployType {
	case "helm":
		pluginInfo = os.Getenv(util.K8sPlugin) + ":" + os.Getenv(util.K8sPluginPort)
	default:
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.DeployTypeIsNotHelmBased)
		return
	}

	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	response, err := adapter.Query(accessToken, appInsId, appInfoRecord.HostIp)
	util.ClearByteArray(bKey)
	if err != nil {
		log.Info("Query failed")
		return
	}
	c.Data["json"] = response
	c.ServeJSON()
}

// Query KPI
func (c *LcmController) QueryKPI() {
	var metricInfo models.MetricInfo

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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
	util.ClearByteArray(bKey)
	_, err = c.getTenantId(clientIp)
	if err != nil {
		return
	}
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		return
	}
	prometheusPort := util.GetAppConfig("promethuesPort")
	cpu, errCpu := getHostInfo(util.HttpUrl + hostIp + ":" + prometheusPort + util.CpuQuery)

	if errCpu != nil {
		log.Fatalln(errCpu)
	}
	mem, errMem := getHostInfo(util.HttpUrl + hostIp + ":" + prometheusPort + util.MemQuery)
	if errMem != nil {
		log.Fatalln(errMem)
	}
	disk, err := getHostInfo(util.HttpUrl + hostIp + ":" + prometheusPort + util.DiskQuery)
	if err != nil {
		log.Fatalln(err)
	}
	metricInfo.CpuUsage = cpu
	metricInfo.MemUsage = mem
	metricInfo.DiskUsage = disk
	metricInfoJson, err := json.Marshal(metricInfo)
	if err != nil {
		log.Info("Failed to json marshal")
		return
	}
	log.Info("metricInfoJson", metricInfoJson)
	log.Info("appJson", metricInfoJson)
	c.ServeJSON()
}

// Query KPI
func getHostInfo(url string) (string, error) {
	//url
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	body, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		return "", err2
	}
	log.Info("response is received")

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return string(body), nil
	}
	return "", errors.New("created failed, status is " + strconv.Itoa(resp.StatusCode))
}

// Query Mep capabilities
func (c *LcmController) QueryMepCapabilities() {
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateIpv4Address(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
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
	util.ClearByteArray(bKey)
	_, err = c.getTenantId(clientIp)
	if err != nil {
		return
	}
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		return
	}

	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	mepPort := util.GetAppConfig("mepPort")
	mepCapabilities, err := http.Get(util.HttpUrl + hostIp + ":" + mepPort + "/mec/v1/mgmt/tenant/" + tenantId + "/hosts/" + hostIp + ":" + mepPort + "/mep-capabilities")

	mepJson, err := json.Marshal(mepCapabilities)

	if mepCapabilities.StatusCode >= 200 && mepCapabilities.StatusCode <= 299 {
		c.ServeJSON()
	}
	log.Info("appJson", mepJson)
	return
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

	var deployType string
	templateMf, err := ioutil.ReadFile(mainServiceTemplateMf)
	if err != nil {
		c.writeErrorResponse("Failed to read file", util.StatusInternalServerError)
	}

	jsondata, err := yaml.YAMLToJSON(templateMf)
	if err != nil {
		c.writeErrorResponse("failed to convert from YAML to JSON", util.StatusInternalServerError)
	}

	helmDeploy, _, _, _ := jsonparser.Get(jsondata, util.NonManoArtifactSets, "applcm_helm_chart_deployment")
	k8sDeploy, _, _, _ := jsonparser.Get(jsondata, util.NonManoArtifactSets, "applcm_k8s_chart_deployment")
	vmDeploy, _, _, _ := jsonparser.Get(jsondata, util.NonManoArtifactSets, "applcm_VM_chart_deployment")

	if helmDeploy != nil {
		deployType = "helm"
	} else if k8sDeploy != nil {
		deployType = "kubernetes"
	} else if vmDeploy != nil {
		deployType = "vm"
	}
	return deployType, nil
}

// Opens package
func (c *LcmController) openPackage(packagePath string) {
	zipReader, _ := zip.OpenReader(packagePath)
	if len(zipReader.File) > util.TooManyFile {
		c.writeErrorResponse("Too many files contains in zip file", util.StatusInternalServerError)
	}
	var totalWrote int64
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

		isContinue, wrote := c.extractFiles(file, zippedFile, totalWrote)
		if isContinue {
			continue
		}
		totalWrote = wrote
	}
}

// Extract files
func (c *LcmController) extractFiles(file *zip.File, zippedFile io.ReadCloser, totalWrote int64) (bool, int64) {
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

// Make target directory
func (c *LcmController) makeTargetDirectory(clientIp string, packageName string) error {
	err := os.Mkdir(PackageFolderPath+packageName, 0750)
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
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
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

	readErr := c.Db.ReadData(appInfoRecord, util.AppInsId)
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
		c.handleLoggingForError(clientIp, util.BadRequest, "HostIp address is invalid")
		return "", err
	}
	return hostIp, nil
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
		pluginInfo := os.Getenv(util.K8sPlugin) + ":" + os.Getenv(util.K8sPluginPort)
		return artifact, pluginInfo, nil
	default:
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.DeployTypeIsNotHelmBased)
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
func (c *LcmController) insertOrUpdateAppInfoRecord(appInsId, hostIp, deployType, clientIp, tenantId string) error {
	appInfoRecord := &models.AppInfoRecord{
		AppInsId:   appInsId,
		HostIp:     hostIp,
		DeployType: deployType,
		TenantId:   tenantId,
	}

	count, err := c.Db.QueryCountForAppInfo("app_info_record", util.TenantId, tenantId)
	if err != nil {
		return err
	}

	if count > util.MAX_NUMBER_OF_RECORDS {
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
		return err
	}

	if count > util.MAX_NUMBER_OF_RECORDS {
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
func (c *LcmController) deleteTenantRecord(tenantId string) error {
	tenantRecord := &models.TenantInfoRecord{
		TenantId: tenantId,
	}

	count, err := c.Db.QueryCountForAppInfo("app_info_record", util.TenantId, tenantId)
	if err != nil {
		return err
	}
	if count == 0 {
		err = c.Db.DeleteData(tenantRecord, util.TenantId)
		if err != nil {
			return err
		}
	}
	return nil
}

// Get input parameters
func (c *LcmController) getInputParameters(clientIp string) (string, string, multipart.File,
	*multipart.FileHeader, string, error) {
	hostIp, err := c.getHostIP(clientIp)
	if err != nil {
		return "", "", nil, nil, "", err
	}

	appInsId, err := c.getAppInstId(clientIp)
	if err != nil {
		return "", "", nil, nil, "", err
	}

	file, header, err := c.getFile(clientIp)
	if err != nil {
		return "", "", nil, nil, "", err
	}
	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		return "", "", nil, nil, "", err
	}

	return hostIp, appInsId, file, header, tenantId, nil
}

// To display log for received message
func (c *LcmController) displayReceivedMsg(clientIp string) {
	log.Info("Received message from ClientIP [" + clientIp + "] Operation [" + c.Ctx.Request.Method + "]" +
		" Resource [" + c.Ctx.Input.URL() + "]")
}
