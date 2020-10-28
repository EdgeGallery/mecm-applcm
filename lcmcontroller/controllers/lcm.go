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
	"lcmcontroller/models"
	"lcmcontroller/pkg/dbAdapter"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
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

	err = util.ValidateFileExtensionEmpty(header.Filename)
	if err != nil || len(header.Filename) > util.MaxFileNameSize {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"File shouldn't contains any extension or filename is larger than max size")
		return
	}

	err = util.ValidateFileSize(header.Size, util.MaxConfigFile)
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "File size is larger than max size")
		return
	}

	err = c.validateYamlFile(clientIp, file)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	pluginInfo, err := getPluginInfo()
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetPluginInfo)
		return
	}

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
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return
	}

	c.ServeJSON()
}

// Validate kubeconfig file
func (c *LcmController) validateYamlFile(clientIp string, file multipart.File) error {

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "Failed to copy file into buffer")
		return err
	}

	_, err := yaml.YAMLToJSON(buf.Bytes())
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "KubeConfig file validation is failed")
		return err
	}
	return nil
}

// Get plugin info
func getPluginInfo() (string, error) {
	k8sPlugin := util.GetK8sPlugin()
	name, err := util.ValidateServiceName(k8sPlugin)
	if err != nil || !name {
		return "", errors.New("service name is not valid")
	}

	k8sPluginPort := util.GetK8sPluginPort()
	port, err := util.ValidatePort(k8sPluginPort)
	if err != nil || !port {
		return "", errors.New(util.PortIsNotValid)
	}
	pluginInfo := k8sPlugin + ":" + k8sPluginPort
	return pluginInfo, nil
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

	pluginInfo, err := getPluginInfo()
	if err != nil {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetPluginInfo)
		return
	}

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
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
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

	err = util.ValidateFileExtensionCsar(header.Filename)
	if err != nil || len(header.Filename) > util.MaxFileNameSize {
		util.ClearByteArray(bKey)
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
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

	pkgPath := PackageFolderPath + header.Filename
	err = c.createPackagePath(pkgPath, clientIp, file)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	packageName := c.openPackage(pkgPath)
	var mainServiceTemplateMf = PackageFolderPath + packageName + "/MainServiceTemplate.mf"
	deployType, err := c.getApplicationDeploymentType(mainServiceTemplateMf)
	if err != nil {
		util.ClearByteArray(bKey)
		c.removeCsarFiles(packageName, header, clientIp)
		return
	}

	artifact, pluginInfo, err := c.getArtifactAndPluginInfo(deployType, packageName, clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		c.removeCsarFiles(packageName, header, clientIp)
		return
	}

	ak, sk, err := util.GenerateAkSk()
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"Failed to generate ak sk values")
		return
	}

	var akSkAppInfo models.AppAuthConfig
	akSkAppInfo.AppInsId = appInsId
	akSkAppInfo.Ak = ak
	akSkAppInfo.Sk = sk
	err = c.InstantiateApplication(pluginInfo, hostIp, artifact, clientIp, accessToken, akSkAppInfo)
	util.ClearByteArray(bKey)
	c.removeCsarFiles(packageName, header, clientIp)
	if err != nil {
		return
	}

	err = c.insertOrUpdateTenantRecord(clientIp, tenantId)
	if err != nil {
		return
	}
	err = c.insertOrUpdateAppInfoRecord(appInsId, hostIp, deployType, clientIp, tenantId)
	if err != nil {
		return
	}
	c.ServeJSON()
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
		pluginInfo, err = getPluginInfo()
		if err != nil {
			util.ClearByteArray(bKey)
			c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetPluginInfo)
			return
		}
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
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
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
		pluginInfo, err = getPluginInfo()
		if err != nil {
			util.ClearByteArray(bKey)
			c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetPluginInfo)
			return
		}
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
	}
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

	hostIp, prometheusPort, err := c.getInputParametersQueryKpi(clientIp)
	if err != nil {
		return
	}

	cpuUtilization, err := c.getCpuUsage(hostIp, prometheusPort, clientIp)
	if err != nil {
		return
	}

	memUsage, err := c.getMemoryUsage(hostIp, prometheusPort, clientIp)
	if err != nil {
		return
	}

	diskUtilization, err := c.diskUsage(hostIp, prometheusPort, clientIp)
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
	}
}

// Query KPI
func getHostInfo(url string) (string, error) {
	var resp *http.Response
	var err error

	if util.GetAppConfig("query_ssl_enable") == "true" {
		url = util.HttpsUrl + url
		req, errNewRequest := http.NewRequest("", url, nil)
		if errNewRequest != nil {
			return "", errNewRequest
		}
		resp, err = util.DoRequest(req)
		if err != nil {
			return "", err
		}
	} else {
		url = util.HttpUrl + url
		resp, err = http.Get(url)
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
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
	hostIp, err := c.getUrlHostIP(clientIp)
	if err != nil {
		return
	}

	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	mepPort := util.GetMepPort()
	port, err := util.ValidatePort(mepPort)
	if err != nil || !port {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.PortIsNotValid)
		return
	}

	mepCapabilities, err := getHostInfo(hostIp + ":" + mepPort + util.BaseUriMec + tenantId + "/hosts/" + hostIp + util.CapabilityUri)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "invalid mepCapabilities query")
		return
	}

	_, err = c.Ctx.ResponseWriter.Write([]byte(mepCapabilities))
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
	}
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
		return "", err
	}

	jsondata, err := yaml.YAMLToJSON(templateMf)
	if err != nil {
		c.writeErrorResponse("failed to convert from YAML to JSON", util.StatusInternalServerError)
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
	filePath := zipReader.Reader.File[0].FileHeader.Name
	dirPath := strings.Split(filePath, "/")
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

	return dirPath[0]
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

// Instantiate application
func (c *LcmController) InstantiateApplication(pluginInfo string, hostIp string,
	artifact string, clientIp string, accessToken string, akSkAppInfo models.AppAuthConfig) error {
	client, err := pluginAdapter.GetClient(pluginInfo)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetClient)
		return err
	}
	adapter := pluginAdapter.NewPluginAdapter(pluginInfo, client)
	err, _ = adapter.Instantiate(hostIp, artifact, accessToken, akSkAppInfo)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
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

		pluginInfo, err := getPluginInfo()
		if err != nil {
			c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToGetPluginInfo)
			return "", "", err
		}
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

	if count > util.MaxNumberOfRecords {
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

	if count > util.MaxNumberOfRecords {
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

// Returns the utilization details
func (c *LcmController) metricValue(statInfo models.KpiModel) (metricResponse map[string]interface{}, err error) {
	clientIp := c.Ctx.Input.IP()
	err = util.ValidateIpv4Address(clientIp)
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

func (c *LcmController) getInputParametersQueryKpi(clientIp string) (string, string, error) {
	_, err := c.getTenantId(clientIp)
	if err != nil {
		return "", "", err
	}
	hostIp, err := c.getUrlHostIP(clientIp)
	if err != nil {
		return "", "", err
	}
	prometheusPort := util.GetPrometheusPort()
	port, err := util.ValidatePort(prometheusPort)
	if err != nil || !port {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.PortIsNotValid)
		return "", "", err
	}
	return hostIp, prometheusPort, nil
}

func (c *LcmController) getCpuUsage(hostIp, prometheusPort, clientIp string) (cpuUtilization map[string]interface{}, err error) {
	var statInfo models.KpiModel

	cpu, errCpu := getHostInfo(hostIp + ":" + prometheusPort + util.CpuQuery)
	if errCpu != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "invalid cpu query")
		return cpuUtilization, nil
	}
	err = json.Unmarshal([]byte(cpu), &statInfo)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, util.UnMarshalError)
		return cpuUtilization, nil
	}
	cpuUtilization, err = c.metricValue(statInfo)
	if err != nil {
		return cpuUtilization, nil
	}
	return cpuUtilization, nil
}

func (c *LcmController) getMemoryUsage(hostIp, prometheusPort, clientIp string) (memUsage map[string]interface{}, err error) {
	var statInfo models.KpiModel

	mem, err := getHostInfo(hostIp + ":" + prometheusPort + util.MemQuery)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "invalid memory query")
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

func (c *LcmController) diskUsage(hostIp string, prometheusPort, clientIp string) (diskUtilization map[string]interface{}, err error) {
	var statInfo models.KpiModel

	disk, err := getHostInfo(hostIp + ":" + prometheusPort + util.DiskQuery)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, "invalid disk query")
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
