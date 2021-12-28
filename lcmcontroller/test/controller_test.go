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

package test

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/stretchr/testify/assert"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"io/ioutil"
	"lcmcontroller/controllers"
	"lcmcontroller/models"
	"lcmcontroller/pkg/dbAdapter"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

var (
	filePermission                    os.FileMode = 0750
	directory                                     = "/packages/"
	tenantIdentifier                              = "e921ce54-82c8-4532-b5c6-8516cf75f7a6"
	appInstanceIdentifier                         = "e921ce54-82c8-4532-b5c6-8516cf75f7a4"
	packageId                                     = "e261211d80d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98"
	appName                                       = "postioning-service"
	queryFailed                                   = "Query failed"
	queryKpiFailed                                = "QueryKpi failed"
	handleLoggingFailure                          = "Handle logging failure is success"
	deleteMecHostSuccess                          = "Delete mec host is successful"
	deleteOper                                    = "DELETE"
	hostsPath                                     = "https://edgegallery:8094/lcmcontroller/v1/tenants/" + tenantIdentifier + "/hosts"
	packageName                                   = "package"
	packages                                      = "/packages"
	tenantsPath                                   = "https://edgegallery:8094/lcmcontroller/v1/tenants/"
	tenantsPathV2                                 = "https://edgegallery:8094/lcmcontroller/v2/tenants/"
	appInstances                                  = "/app_instances/"
	appUrlPath                                    = tenantsPath + tenantIdentifier + appInstances
	appUrlPathV2                                  = tenantsPathV2 + tenantIdentifier + appInstances
	appUrlPathId                                  = tenantsPath + tenantIdentifier + appInstances + appInstanceIdentifier
	appUrlPathIdV2                                = tenantsPathV2 + tenantIdentifier + appInstances + appInstanceIdentifier
	originKey                                     = "origin"
	originVal                                     = "MEPM"
	appNameKey                                    = "appName"
	packageIdKey                                  = "packageId"
	hostIpKey                                     = "hostIp"
	sync_deleted_request                          = "https://edgegallery:8094/lcmcontroller/v1/tenants/hosts/sync_deleted"
	configuration_request                         = "https://edgegallery:8094/lcmcontroller/v1/configuration"
	uploadConfigRequestV2                         = "https://edgegallery:8094/lcmcontroller/v2/configuration"
	configfile                                    = "configFile"
	deletePackageSuccess                          = "{\"data\":null,\"retCode\":0,\"message\":\"Deleted host application package successfully\",\"params\":null}"
	getClientIpAndIsPermitted                     = "GetClientIpAndIsPermitted"
	tenantId                                      = ":tenantId"
	terminate                                     = "terminate"
	file                                          = "file"
	instantiate                                   = "instantiate"
	uploadPackageFailed                           = "Upload package failed"
	distributePackageFailed                       = "Distribute package failed"
	getClientIpAndValidateAccessToken             = "GetClientIpAndValidateAccessToken"
	getTenantId                                   = "GetTenantId"
	getVim                                        = "GetVim"
	getAppInfoRecord                              = "GetAppInfoRecord"
	getAppInstId                                  = "GetAppInstId"
	insertOrUpdateData                            = "InsertOrUpdateData"
	terminateFailed                               = "Terminate failed"
	deleteTenantRecord                            = "DeleteTenantRecord"
	readData                                      = "ReadData"
	clientIp                                      = "172.1.1.1"
	err                                           = errors.New("error")
	getInputParametersForChangeKey                = "GetInputParametersForChangeKey"
	username                                      = "testUser"
	tenantRole                                    = "ROLE_MECM_TENANT"
	adminRole                                     = "ROLE_MECM_ADMIN"
	deleteData                                    = "DeleteData"
	getUserName                                   = "GetUserName"
	errorNotFond                                  = "not found"
	queryCountForTable                            = "QueryCountForTable"
	getInputParametersForUploadCfg                = "GetInputParametersForUploadCfg"
	isPermitted                                   = "IsPermitted"
	queryCount                                    = "QueryCount"
	getPluginAdapter                              = "GetPluginAdapter"
)

func TestLcmOperation(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
		return &mockClient{}, nil
	})
	defer patch1.Reset()

	var c *beego.Controller
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), "ServeJSON", func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(util.DoRequest, func(_ *http.Request) (*http.Response, error) {
		// do nothing
		return &http.Response{
			Body:       ioutil.NopCloser(bytes.NewBufferString("lcmcontroller")),
			StatusCode: 200,
		}, nil
	})
	defer patch3.Reset()

	// Common steps
	baseDir, _ := os.Getwd()
	path := baseDir + "/positioning_with_mepagent_new.zip"
	controllers.PackageFolderPath = baseDir + directory
	_ = os.Mkdir(baseDir+directory, filePermission)
	extraParams := map[string]string{
		hostIpKey:    ipAddress,
		packageIdKey: packageId,
		appNameKey:   appName,
		originKey:    originVal,
	}

	testDb := &MockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords:         make(map[string]models.TenantInfoRecord),
		appPackageRecords:     make(map[string]models.AppPackageRecord),
		mecHostRecords:        make(map[string]models.MecHost),
		appPackageHostRecords: make(map[string]models.AppPackageHostRecord)}

	//Upload package
	testUploadPackage(t, extraParams, path, testDb)
	testUploadPackageV2(t, extraParams, path, testDb)

	// Test Add mec host
	testAddMecHost(t, extraParams, testDb)

	// Test update mec host
	testUpdateMecHost(t, extraParams, testDb)

	// Test get mec host
	testGetMecHost(t, nil, "", testDb)

	// Test sync updated mec host record
	testSyncUpdatedMecHostRec(t, nil, "", testDb)

	// Test the Distribute package
	testDistributePackage(t, extraParams, testDb)
	testDistributePackageV2(t, extraParams, testDb)

	// Test Distribution status
	testDistributionStatus(t, extraParams, testDb)
	testDistributionStatusV2(t, extraParams, testDb)

	// Test instantiate
	testInstantiate(t, extraParams, testDb)
	testInstantiateV2(t, extraParams, testDb)

	// Test get app instance
	testGetAppInstance(t, nil, "", testDb)

	// Test sync updated app instances record
	testSyncUpdatedAppInstRec(t, nil, "", testDb)

	// Test sync updated app package updated record
	testSynchronizeAppPackageUpdatedRecord(t, nil, "", testDb)
	testSynchronizeAppPackageUpdatedRecordV2(t, nil, "", testDb)

	// Test sync stale app package updated record
	testSynchronizeAppPackageStaleRecord(t, nil, "", testDb)
	testSynchronizeAppPackageStaleRecordv2(t, nil, "", testDb)
	// Test query
	testQuery(t, nil, "", testDb, "Success")

	// Test workload events
	testWorkloadEvents(t, nil, "", testDb, "Success")

	// Test terminate
	testTerminate(t, nil, "", testDb)
	testTerminateV2(t, nil, "", testDb)

	//Test sync stale app information records
	testSynchronizeStaleRecord(t, nil, "", testDb)

	// Test sync updated mec host record
	testSyncMecHostStaleRecord(t, nil, "", testDb)

	// Test instantiate
	testInstantiate(t, extraParams, testDb)
	testInstantiateV2(t, extraParams, testDb)

	// Test delete package on host
	testDeletePackageOnHost(t, extraParams, testDb)
	testDeletePackageOnHostV2(t, extraParams, testDb)

	// Test delete package
	testDeletePackage(t, extraParams, testDb)
	testDeletePackageV2(t, extraParams, testDb)

	// Test Batch terminate
	testBatchTerminate(t, nil, testDb)

	// Test delete mec host
	testDeleteMecHost(t, extraParams, testDb)

	// Test error scenarios
	testErrorScenarios(t, extraParams, testDb)

	// Common cleaning state
	// Clear the created artifacts
	_ = os.RemoveAll(baseDir + directory)
}

func TestConfigOperation(t *testing.T) {

	// Common steps
	// Setting file path
	path, _ := os.Getwd()
	path += "/config"
	// Setting extra parameters
	extraParams := map[string]string{
		hostIpKey:  ipAddress,
		appNameKey: appName,
	}
	testDb := &MockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords:         make(map[string]models.TenantInfoRecord),
		appPackageRecords:     make(map[string]models.AppPackageRecord),
		mecHostRecords:        make(map[string]models.MecHost),
		appPackageHostRecords: make(map[string]models.AppPackageHostRecord)}

	var c *beego.Controller
	patch1 := gomonkey.ApplyMethod(reflect.TypeOf(c), "ServeJSON", func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch1.Reset()

	testAddMecHost(t, extraParams, testDb)

	// Test upload
	testUpload(t, extraParams, path, testDb)
	testUploadV2(t, extraParams, path, testDb)

	// Test removal
	testRemoval(t, extraParams, path, testDb)
	testRemovalV2(t, extraParams, path, testDb)
}

func testQuery(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database, exOutput string) {

	t.Run("TestAppInstanceQuery", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(appUrlPathId, extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		err := errors.New("error")
		accessToken := createToken(tenantIdentifier)
		// Test upload package
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(queryController), getTenantId, func(_ *controllers.LcmController, _ string) (tenantId string, error error) {
			return "123", err
		})
		defer patch1.Reset()
		// Test upload package
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		//for v2

		// Get Request
		queryRequestv2, _ := getHttpRequest(appUrlPathId, extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInputv2 := &context.BeegoInput{Context: &context.Context{Request: queryRequestv2}}
		setParam(queryInputv2)

		// Prepare beego controller
		queryBeegoControllerv2 := beego.Controller{Ctx: &context.Context{Input: queryInputv2, Request: queryRequestv2,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryControllerv2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: queryBeegoControllerv2}}

		// Test query
		queryControllerv2.QueryV2()

		accessToken = createToken(tenantIdentifier)
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(queryControllerv2), getPluginAdapter, func(_ *controllers.LcmControllerV2, _, _ string, _ string) (*pluginAdapter.PluginAdapter,
			error) {
			return nil, err
		})
		defer patch7.Reset()
		// Test upload package
		queryBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryControllerv2.QueryV2()

		accessToken = createToken(tenantIdentifier)
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(queryControllerv2), getVim, func(_ *controllers.LcmControllerV2, _ string, _ string) (string, error) {
			return "nil", err
		})
		defer patch6.Reset()
		// Test upload package
		queryBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryControllerv2.QueryV2()

		accessToken = createToken(tenantIdentifier)
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(queryControllerv2), getAppInfoRecord, func(_ *controllers.LcmControllerV2, _ string, _ string) (*models.AppInfoRecord, error) {
			return nil, err
		})
		defer patch4.Reset()
		// Test upload package
		queryBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryControllerv2.QueryV2()

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		queryBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryControllerv2.QueryV2()

	})
}

func testQueryKpi(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database, exOutput string) {

	t.Run("TestAppInstanceQueryKpi", func(t *testing.T) {

		// Get Request
		queryKpiRequest, _ := getHttpRequest(appUrlPathId, extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryKpiInput := &context.BeegoInput{Context: &context.Context{Request: queryKpiRequest}}
		setParam(queryKpiInput)

		// Prepare beego controller
		queryKpiBeegoController := beego.Controller{Ctx: &context.Context{Input: queryKpiInput, Request: queryKpiRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryKpiController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: queryKpiBeegoController}}

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryKpiController.Ctx.ResponseWriter.Status, queryKpiFailed)
		response := queryKpiController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
		assert.NotEqual(t, exOutput, response.Body.String(), queryKpiFailed)
		//assert.Equal(t, exOutput, response.Body.String(), queryKpiFailed)

		err1 := errors.New("error")
		accessToken := createToken(tenantIdentifier)
		// Test upload package
		queryKpiBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		//queryKpiController.QueryKPI()

		accessToken = createToken(tenantIdentifier)
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(queryKpiController), "GetUrlHostIP", func(_ *controllers.LcmController, _ string) (string, error) {
			return "", err1
		})
		defer patch2.Reset()
		// Test upload package
		queryKpiBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		//for v2

		// Get Request
		queryKpiRequest2, _ := getHttpRequest(appUrlPathId, extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryKpiV2Input := &context.BeegoInput{Context: &context.Context{Request: queryKpiRequest2}}
		setParam(queryKpiV2Input)

		// Prepare beego controller
		queryKpiBeegoControllerV2 := beego.Controller{Ctx: &context.Context{Input: queryKpiV2Input, Request: queryKpiRequest2,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryKpiController2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: queryKpiBeegoControllerV2}}

		response = queryKpiController2.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
		assert.NotEqual(t, exOutput, response.Body.String(), queryKpiFailed)

		accessToken = createToken(tenantIdentifier)
		patch8 := gomonkey.ApplyMethod(reflect.TypeOf(queryKpiController2), getPluginAdapter, func(_ *controllers.LcmControllerV2, _, _ string, _ string) (*pluginAdapter.PluginAdapter,
			error) {
			return nil, err1
		})
		defer patch8.Reset()
		// Test upload package
		queryKpiBeegoControllerV2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryKpiController2.QueryKPI()

		accessToken = createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(queryKpiController2), getVim, func(_ *controllers.LcmControllerV2, _ string, _ string) (string, error) {
			return "", err1
		})
		defer patch1.Reset()
		// Test upload package
		queryKpiBeegoControllerV2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryKpiController2.QueryKPI()

	})
}

func testSyncUpdatedAppInstRec(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSyncUpdatedAppInstRec", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(appUrlPath+"sync_updated", extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//for v2

		// Get Request
		queryRequestv2, _ := getHttpRequest(appUrlPath+"sync_updated", extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInputv2 := &context.BeegoInput{Context: &context.Context{Request: queryRequestv2}}
		setParam(queryInputv2)

		// Prepare beego controller
		queryBeegoControllerv2 := beego.Controller{Ctx: &context.Context{Input: queryInputv2, Request: queryRequestv2,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryControllerv2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: queryBeegoControllerv2}}

		// Test query
		queryControllerv2.SynchronizeUpdatedRecord()

	})
}

func testSynchronizeAppPackageStaleRecord(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSynchronizeAppPackageStaleRecord", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(tenantsPath+tenantIdentifier+"/packages/sync_deleted", extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//Newly added test cases for failure case checking

		//tenantid empty failure case
		queryBeegoController.Ctx.Input.SetParam(tenantId, "")
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//client ip empty failure case
		queryBeegoController.Ctx.Request.Header.Set("X-Forwarded-For", "")
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//Access_token failure case
		s := string([]byte{1})
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken, s)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
	})
}

func testSynchronizeAppPackageStaleRecordv2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSynchronizeAppPackageStaleRecordv2", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(tenantsPathV2+tenantIdentifier+"/packages/sync_deleted", extraParams, "file", path, "GET", []byte(""))

		accessToken := createTokenAdmin(tenantIdentifier)
		queryRequest.Header.Set("access_token", accessToken)

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Test query
		queryController.SynchronizeAppPackageStaleRecord()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//Newly added test cases for failure case checking

		//tenantid empty failure case
		queryBeegoController.Ctx.Input.SetParam(tenantId, "")
		queryController.SynchronizeAppPackageStaleRecord()
		assert.Equal(t, 200, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//client ip empty failure case
		queryBeegoController.Ctx.Request.Header.Set("X-Forwarded-For", "")
		queryController.SynchronizeAppPackageStaleRecord()
		assert.Equal(t, 200, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//Access_token failure case
		s := string([]byte{1})
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken, s)
		queryController.SynchronizeAppPackageStaleRecord()
		assert.Equal(t, 200, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

	})
}

func testSynchronizeAppPackageUpdatedRecord(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSynchronizeAppPackageUpdatedRecord", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(tenantsPath+tenantIdentifier+"/packages/sync_updated", extraParams,
			"file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

	})
}

func testSynchronizeAppPackageUpdatedRecordV2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSynchronizeAppPackageUpdatedRecord", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(tenantsPathV2+tenantIdentifier+"/packages/sync_updated", extraParams,
			"file", path, "GET", []byte(""))
		accessToken := createTokenAdmin(tenantIdentifier)
		queryRequest.Header.Set("access_token", accessToken)

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Test query
		queryController.SynchronizeAppPackageUpdatedRecord()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		err := errors.New("error")

		accessToken = createToken(tenantIdentifier)
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(queryController.Db), insertOrUpdateData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch6.Reset()
		// Test upload package
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryController.DeletePackage()
		var appPackagesSync []*models.AppPackageRecord
		queryController.InsertAppPackageRec(appPackagesSync)

		accessToken = createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(queryController), "InsertAppPackageRec", func(_ *controllers.LcmControllerV2, _ []*models.AppPackageRecord) error {
			return err
		})
		defer patch3.Reset()
		// Test upload package
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryController.SynchronizeAppPackageUpdatedRecord()

		accessToken = createToken(tenantIdentifier)
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(queryController), "SendAppPkgSyncRecords", func(_ *controllers.LcmControllerV2, _ []*models.AppPackageRecord, _ string) error {
			return err
		})
		defer patch2.Reset()
		// Test upload package
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryController.SynchronizeAppPackageUpdatedRecord()

		accessToken = createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(queryController), getTenantId, func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "123", err
		})
		defer patch1.Reset()
		// Test upload package
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryController.SynchronizeAppPackageUpdatedRecord()
	})
}

func testSyncUpdatedMecHostRec(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSyncUpdatedMecHostRec", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/hosts/sync_updated",
			extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Test query
		queryController.SynchronizeMecHostUpdatedRecord()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
	})
}

func testSynchronizeStaleRecord(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSynchronizeStaleRecord", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(sync_deleted_request,
			extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//for v2

		// Get Request
		queryRequestv2, _ := getHttpRequest(sync_deleted_request,
			extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInputv2 := &context.BeegoInput{Context: &context.Context{Request: queryRequestv2}}
		setParam(queryInputv2)

		// Prepare beego controller
		queryBeegoControllerv2 := beego.Controller{Ctx: &context.Context{Input: queryInputv2, Request: queryRequestv2,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryControllerv2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: queryBeegoControllerv2}}

		// Test query
		queryControllerv2.SynchronizeStaleRecord()

	})
}

func testSyncMecHostStaleRecord(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSyncMecHostStaleRecord", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(sync_deleted_request,
			extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Test query
		queryController.SynchronizeMecHostStaleRecord()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
	})
}

func testWorkloadEvents(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database,
	exOutput string) {

	t.Run("TestWorkloadEventsQuery", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(appUrlPathId+"workload/events", extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)

		err := errors.New("error")
		accessToken := createToken(tenantIdentifier)
		patch22 := gomonkey.ApplyMethod(reflect.TypeOf(queryController), getAppInstId, func(_ *controllers.LcmController, _ string) (_ string, error error) {
			return "", err
		})
		defer patch22.Reset()
		// Test upload package
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		//for v2

		// Get Request
		queryRequestv2, _ := getHttpRequest(appUrlPathId+"workload/events", extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInputv2 := &context.BeegoInput{Context: &context.Context{Request: queryRequestv2}}
		setParam(queryInputv2)

		// Prepare beego controller
		queryBeegoControllerv2 := beego.Controller{Ctx: &context.Context{Input: queryInputv2, Request: queryRequestv2,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryControllerv2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: queryBeegoControllerv2}}

		// Test query
		queryControllerv2.GetWorkloadDescription()

		accessToken = createToken(tenantIdentifier)
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(queryControllerv2), getPluginAdapter, func(_ *controllers.LcmControllerV2, _, _ string, _ string) (*pluginAdapter.PluginAdapter,
			error) {
			return nil, err
		})
		defer patch5.Reset()
		// Test upload package
		queryBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryControllerv2.GetWorkloadDescription()

		accessToken = createToken(tenantIdentifier)
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(queryControllerv2), getVim, func(_ *controllers.LcmControllerV2, _ string, _ string) (string, error) {
			return "nil", err
		})
		defer patch4.Reset()
		// Test upload package
		queryBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryControllerv2.GetWorkloadDescription()

		accessToken = createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(queryControllerv2), getAppInfoRecord, func(_ *controllers.LcmControllerV2, _ string, _ string) (*models.AppInfoRecord, error) {
			return nil, err
		})
		defer patch3.Reset()
		// Test upload package
		queryBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryControllerv2.GetWorkloadDescription()

		accessToken = createToken(tenantIdentifier)
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(queryControllerv2), getAppInstId, func(_ *controllers.LcmControllerV2, _ string) (_ string, error error) {
			return "", err
		})
		defer patch2.Reset()
		// Test upload package
		queryBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryControllerv2.GetWorkloadDescription()

		accessToken = createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(queryControllerv2), getTenantId, func(_ *controllers.LcmControllerV2, _ string) (_ string, error error) {
			return "", err
		})
		defer patch1.Reset()
		// Test upload package
		queryBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		queryControllerv2.GetWorkloadDescription()

	})
}

func testTerminate(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {
	t.Run("TestAppInstanceTerminate", func(t *testing.T) {

		// Terminate Request
		terminateRequest, _ := getHttpRequest(appUrlPathId+terminate, extraParams, "file",
			path, "POST", []byte(""))

		// Prepare Input
		terminateInput := &context.BeegoInput{Context: &context.Context{Request: terminateRequest}}
		setParam(terminateInput)

		// Prepare beego controller
		terminateBeegoController := beego.Controller{Ctx: &context.Context{Input: terminateInput,
			Request: terminateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		terminateController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: terminateBeegoController}}

		err := errors.New("error")

		accessToken := createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController), getAppInstId, func(_ *controllers.LcmController, _ string) (_ string, error error) {
			return "", err
		})
		defer patch1.Reset()
		// Test upload package
		terminateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
	})
}

func testTerminateV2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {
	t.Run("TestAppInstanceTerminate", func(t *testing.T) {

		// Terminate Request
		terminateRequest, _ := getHttpRequest(appUrlPathId+terminate, extraParams, "file",
			path, "POST", []byte(""))

		// Prepare Input
		terminateInput := &context.BeegoInput{Context: &context.Context{Request: terminateRequest}}
		setParam(terminateInput)

		// Terminate Request
		terminateRequestv2, _ := getHttpRequest(appUrlPathIdV2+terminate, extraParams, "file",
			path, "POST", []byte(""))

		// Prepare Input
		terminateInputv2 := &context.BeegoInput{Context: &context.Context{Request: terminateRequestv2}}
		setParam(terminateInputv2)

		// Prepare beego controller
		terminateBeegoControllerv2 := beego.Controller{Ctx: &context.Context{Input: terminateInputv2,
			Request: terminateRequestv2, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		terminateController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: terminateBeegoControllerv2}}

		// Test query
		terminateController.TerminateV2()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, terminateController.Ctx.ResponseWriter.Status, terminateFailed)

		err := errors.New("error")

		accessToken := createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController), deleteTenantRecord, func(_ *controllers.LcmControllerV2, _, _ string) (error error) {
			return err
		})
		defer patch1.Reset()
		// Test upload package
		terminateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		terminateController.TerminateV2()

		accessToken = createToken(tenantIdentifier)
		patch8 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch8.Reset()
		// Test upload package
		terminateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		terminateController.TerminateV2()
		//clientIp := clientIp
		terminateController.GetMecHostInfoRecord(hostIp, clientIp, tenantIdentifier)

		accessToken = createToken(tenantIdentifier)
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController), "GetMecHostInfoRecord", func(_ *controllers.LcmControllerV2, _ string, _ string, _ string) (*models.MecHost, error) {
			return nil, err
		})
		defer patch7.Reset()
		// Test upload package
		terminateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		terminateController.TerminateV2()
		terminateController.GetVim(clientIp, hostIp)

		accessToken = createToken(tenantIdentifier)
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController), getVim, func(_ *controllers.LcmControllerV2, _ string, _ string) (string, error) {
			return "", err
		})
		defer patch2.Reset()
		// Test upload package
		terminateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		terminateController.TerminateV2()

		accessToken = createToken(tenantIdentifier)
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController), getAppInfoRecord, func(_ *controllers.LcmControllerV2, _ string, _ string) (*models.AppInfoRecord, error) {
			return nil, err
		})
		defer patch5.Reset()
		// Test upload package
		terminateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		terminateController.TerminateV2()

		accessToken = createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController), getAppInstId, func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch3.Reset()
		// Test upload package
		terminateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		terminateController.TerminateV2()

		accessToken = createToken(tenantIdentifier)
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController), "IsPermitted", func(_ *controllers.LcmControllerV2, _, _ string) (string, error) {
			return "", err
		})
		defer patch4.Reset()
		// Test upload package
		terminateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		terminateController.TerminateV2()
	})
}

func testBatchTerminate(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestBatchTerminate", func(t *testing.T) {
		// POST Request
		batchTerminateRequest, _ := getHttpRequest(appUrlPath+"batchTerminate", extraParams,
			"file", "", "POST", []byte(""))

		requestBody, _ := json.Marshal(map[string]string{
			"appInstances": appInstanceIdentifier,
		})

		// Prepare Input
		batchTerminateInput := &context.BeegoInput{Context: &context.Context{Request: batchTerminateRequest}, RequestBody: requestBody}
		setParam(batchTerminateInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: batchTerminateInput,
			Request: batchTerminateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test instantiate
		instantiateController.BatchTerminate()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 404, instantiateController.Ctx.ResponseWriter.Status, "Batch terminate failed")

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		instantiateController.BatchTerminate()

		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch2.Reset()

		patch3 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return err
		})
		defer patch3.Reset()
		instantiateController.BatchTerminate()

	})
}

func testInstantiate(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestAppInstanceInstantiate", func(t *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest(appUrlPath+instantiate, extraParams,
			"file", "", "POST", []byte(""))

		requestBody, _ := json.Marshal(map[string]string{
			hostIpKey:    ipAddress,
			packageIdKey: packageId,
			appNameKey:   "testApplication",
			originKey:    originVal,
		})

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest}, RequestBody: requestBody}
		setParam(instantiateInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: instantiateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Check for success case wherein the status value will be default i.e. 0
		assert.NotEqual(t, instantiateController.Ctx.ResponseWriter.Status, "Instantiation failed")
		//assert.NotEqual()
		err := errors.New("error")

		accessToken := createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), getVim,
			func(_ *controllers.LcmController, _ string, _ string, _ string) (_ string, error error) {
				return "", err
			})
		defer patch3.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		//assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Instantiation failed")

		err1 := *new(error)
		err1 = nil
		accessToken = createToken(tenantIdentifier)
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err1
		})
		defer patch2.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		//assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Instantiation failed")

		accessToken = createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch1.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		patch4 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return errors.New("error")
		})
		defer patch4.Reset()
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		patch5 := gomonkey.ApplyFunc(util.ValidateName, func(_ string, _ string) (bool, error) {
			return true, err
		})
		defer patch5.Reset()
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

	})
}

func testInstantiateV2(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestAppInstanceInstantiate", func(_ *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest(appUrlPathV2+instantiate, extraParams,
			"file", "", "POST", []byte(""))

		requestBody, _ := json.Marshal(map[string]string{
			hostIpKey:    ipAddress,
			packageIdKey: packageId,
			appNameKey:   "testApplication",
			originKey:    originVal,
		})

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest}, RequestBody: requestBody}
		setParam(instantiateInput)
		//for v2

		// POST Request
		instantiateRequestv2, _ := getHttpRequest(appUrlPath+instantiate, extraParams,
			"file", "", "POST", []byte(""))

		// Prepare Input
		instantiateInputv2 := &context.BeegoInput{Context: &context.Context{Request: instantiateRequestv2}, RequestBody: requestBody}
		setParam(instantiateInputv2)

		// Prepare beego controller
		instantiateBeegoControllerv2 := beego.Controller{Ctx: &context.Context{Input: instantiateInputv2,
			Request: instantiateRequestv2, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateControllerv2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoControllerv2}}

		// Test instantiate
		instantiateControllerv2.InstantiateV2()

		//test case-1: for covering DoInstantiate
		patch8 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateControllerv2.Db), queryCount,
			func(_ *MockDb, _ string) (int64, error) {
				return 1, err
			})
		defer patch8.Reset()
		instantiateControllerv2.InstantiateV2()

		accessToken := createToken(tenantIdentifier)
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateControllerv2), getTenantId,
			func(_ *controllers.LcmControllerV2, _ string) (string, error) {
				return "", err
			})
		defer patch4.Reset()
		// Test upload package
		instantiateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateControllerv2.InstantiateV2()

		accessToken = createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateControllerv2), getAppInstId, func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch3.Reset()
		// Test upload package
		instantiateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateControllerv2.InstantiateV2()

		accessToken = createToken(tenantIdentifier)
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateControllerv2), "ValidateInstantiateInputParameters",
			func(_ *controllers.LcmControllerV2, _ string, req models.InstantiateRequest) (string, string, string, string, string, error) {
				return "", "", "", "", "", err
			})
		defer patch2.Reset()
		// Test upload package
		instantiateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateControllerv2.InstantiateV2()

		accessToken = createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateControllerv2), "ValidateToken",
			func(_ *controllers.LcmControllerV2, _ string, _ models.InstantiateRequest, _ string) (string, string, string, string, string, error) {
				return "", "", "", "", "", err
			})
		defer patch1.Reset()
		// Test upload package
		instantiateBeegoControllerv2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateControllerv2.InstantiateV2()

		patch6 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch6.Reset()
		instantiateControllerv2.InstantiateV2()

		patch7 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch7.Reset()
		patch9 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateControllerv2), "ValidateToken",
			func(_ *controllers.LcmControllerV2, _ string, _ models.InstantiateRequest, _ string) (string, string, string, string, string, error) {
				return "", "", "", "", "", nil
			})
		defer patch9.Reset()
		patch10 := gomonkey.ApplyFunc(util.ValidateName, func(_ string, _ string) (bool, error) {
			return false, err
		})
		defer patch10.Reset()
		instantiateControllerv2.InstantiateV2()
	})
}

func testGetAppInstance(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestAppInstanceQuery", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(appUrlPath, extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Test query
		queryController.GetAppInstance()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		response := queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
		assert.Equal(t, "null", response.Body.String(), queryFailed)

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()

		// Test query
		queryController.GetAppInstance()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, queryController.Ctx.ResponseWriter.Status, queryFailed)
	})
}

func testUploadPackage(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestUploadPackage", func(t *testing.T) {

		// Get Request
		url := tenantsPath + tenantIdentifier + packages
		uploadPkgRequest, _ := getHttpRequest(url, extraParams,
			packageName, path, "POST", []byte(""))

		// Prepare Input
		uploadPkgInput := &context.BeegoInput{Context: &context.Context{Request: uploadPkgRequest}}
		setParam(uploadPkgInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadPkgInput,
			Request: uploadPkgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test health check
		instantiateController.HealthCheck()
		// Test Ratelimiter
		r := &util.RateLimiter{}
		rate, _ := limiter.NewRateFromFormatted("200-S")
		r.GeneralLimiter = limiter.New(memory.NewStore(), rate)
		util.RateLimit(r, instantiateController.Ctx)

		accessToken := createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		patch20 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), queryCount, func(_ *MockDb, _ string) (int64, error) {
			return 1, err
		})
		defer patch20.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		//instantiateController.InsertOrUpdateTenantRecord(clientIp3, tenantId)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		// Check for success case wherein the status value will be default i.e. 0
		assert.NotEqual(t, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

		patch30 := gomonkey.ApplyFunc(os.Open, func(_ string) (*os.File, error) {
			return nil, nil
		})
		defer patch30.Reset()

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		patch9 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetFile",
			func(_ *controllers.LcmController, _ string) (file multipart.File, header *multipart.FileHeader, error error) {
				return file, header, err
			})
		defer patch9.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		patch15 := gomonkey.ApplyFunc(os.Open, func(_ string) (*os.File, error) {
			return nil, nil
		})
		defer patch15.Reset()

		accessToken = createToken(tenantIdentifier)

		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
	})
}

func testUploadPackageV2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestUploadPackage", func(t *testing.T) {

		// Get Request
		url := tenantsPathV2 + tenantIdentifier + packages
		uploadPkgRequest, _ := getHttpRequest(url, extraParams,
			packageName, path, "POST", []byte(""))

		// Prepare Input
		uploadPkgInput := &context.BeegoInput{Context: &context.Context{Request: uploadPkgRequest}}
		setParam(uploadPkgInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadPkgInput,
			Request: uploadPkgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test upload package
		instantiateController.UploadPackageV2()

		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

		err := errors.New("error")

		accessToken := createToken(tenantIdentifier)
		patch17 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), "DeleteData", func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch17.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		var clientIp string
		instantiateController.DeleteTenantRecord(clientIp, tenantId)

		accessToken = createToken(tenantIdentifier)
		patch16 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), "QueryCountForTable",
			func(_ *MockDb, tableName, fieldName, fieldValue string) (int64, error) {
				return 1, err
			})
		defer patch16.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()
		instantiateController.DeleteTenantRecord(clientIp, tenantId)
		var distributionStatus string
		var origin string
		instantiateController.InsertOrUpdateAppPkgHostRecord(hostIp, clientIp, tenantId,
			packageId, distributionStatus, origin)

		accessToken = createToken(tenantIdentifier)
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "InsertOrUpdateAppPkgRecord", func(_ *controllers.LcmControllerV2, _, _, _,
			_ string, _ models.AppPkgDetails, _ string) (error error) {
			return err
		})
		defer patch7.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

		accessToken = createToken(tenantIdentifier)
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), insertOrUpdateData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch5.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()
		instantiateController.InsertOrUpdateAppPkgHostRecord(hostIp, clientIp, tenantId,
			packageId, distributionStatus, origin)

		accessToken = createToken(tenantIdentifier)
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), queryCount, func(_ *MockDb, _ string) (int64, error) {
			return 1, err
		})
		defer patch4.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		accessToken = createToken(tenantIdentifier)
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "InsertOrUpdateTenantRecord", func(_ *controllers.LcmControllerV2, _, _ string) (error error) {
			return err
		})
		defer patch6.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

		//patch20 := gomonkey.ApplyFunc(os.Open, func(_ string) (*os.File, error) {
		//	return nil,nil
		//})
		//defer patch20.Reset()
		//
		//// Test instantiate
		////instantiateController.UploadPackageV2()
		//packageDir := "abc"
		//instantiateController.GetPackageDetailsFromPackage(clientIp, packageDir)
		//
		//accessToken = createToken(tenantIdentifier)
		//patch8 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetFileContainsExtension", func(_ *controllers.LcmControllerV2 ,_ string, _ string, _ string) (string, error) {
		//	return "", err
		//})
		//defer patch8.Reset()
		//// Test upload package
		//instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		//instantiateController.UploadPackageV2()
		//
		//accessToken = createToken(tenantIdentifier)
		//patch15 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetPackageDetailsFromPackage", func(_ *controllers.LcmControllerV2 ,_ string,
		//	_ string) (pkgDir models.AppPkgDetails , error error) {
		//	return pkgDir,err
		//})
		//defer patch15.Reset()
		//// Test upload package
		//instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		//instantiateController.UploadPackageV2()
		//
		//// Check for success case wherein the status value will be default i.e. 0
		//assert.Equal(t,200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

		accessToken = createToken(tenantIdentifier)
		patch10 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "CreatePackagePath",
			func(_ *controllers.LcmControllerV2, _ string, _ string, _ multipart.File) (error error) {
				return err
			})
		defer patch10.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		accessToken = createToken(tenantIdentifier)
		patch9 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "SaveApplicationPackage",
			func(_ *controllers.LcmControllerV2, _ string, _ string, _ string,
				_ *multipart.FileHeader, _ multipart.File) (pkgFilePath string, error error) {
				return "", err
			})
		defer patch9.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

		accessToken = createToken(tenantIdentifier)
		patch14 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetFile",
			func(_ *controllers.LcmControllerV2, _ string) (multipart.File, *multipart.FileHeader, error) {
				return nil, nil, err
			})
		defer patch14.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		accessToken = createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetOrigin",
			func(_ *controllers.LcmControllerV2, _ string) (origin string, error error) {
				return "", err
			})
		defer patch1.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

		accessToken = createToken(tenantIdentifier)
		patch23 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), getTenantId, func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch23.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		//clientIp := "172.1.1.1"
		instantiateController.GetInputParametersForUploadPkg(clientIp)
		instantiateController.UploadPackageV2()

		accessToken = createToken(tenantIdentifier)
		patch11 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetPackageId", func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch11.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		accessToken = createToken(tenantIdentifier)
		patch12 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetAppId", func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch12.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		accessToken = createToken(tenantIdentifier)
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetInputParametersForUploadPkg",
			func(_ *controllers.LcmControllerV2, _ string) (appId, packageId, tenantId string, error error) {
				return appId, packageId, "", err
			})
		defer patch2.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

		accessToken = createToken(tenantIdentifier)
		patch18 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "IsTenantAvailable", func(_ *controllers.LcmControllerV2) bool {
			return true
		})
		defer patch18.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()
		instantiateController.IsPermitted(accessToken, clientIp)

		patch3 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return err
		})
		defer patch3.Reset()
		instantiateController.IsPermitted(accessToken, clientIp)

		accessToken = createToken(tenantIdentifier)
		patch13 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "IsPermitted", func(_ *controllers.LcmControllerV2, accessToken, _ string) (string, error) {
			return "", err
		})
		defer patch13.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.UploadPackageV2()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

	})
}

func testAddMecHost(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestAddMecHost", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]string{
			"mechostIp":   ipAddress,
			"mechostName": "edgegallery",
			"zipCode":     "560048",
			"city":        "xian",
			"address":     "xian",
			"affinity":    "shenzhen",
			"userName":    "root",
			"coordinates": "1,2",
			originKey:     originVal,
		})

		// Get Request
		mecHostRequest, _ := getHttpRequest(hostsPath, extraParams,
			packageName, "", "POST", requestBody)

		// Prepare Input
		mecHostInput := &context.BeegoInput{Context: &context.Context{Request: mecHostRequest}, RequestBody: requestBody}
		setParam(mecHostInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: mecHostInput,
			Request: mecHostRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test Add mec host
		instantiateController.AddMecHost()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Add MEC host failed")

		//case-2
		patch5 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return err
		})
		defer patch5.Reset()
		instantiateController.AddMecHost()

		//case-3
		patch6 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return nil
		})
		defer patch6.Reset()
		baseController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}
		instantiateBeegoController.Ctx.Request.Header.Set("name", "testUser")
		patch7 := gomonkey.ApplyFunc(util.ValidateUserName, func(_ string, _ string) (bool, error) {
			return false, err
		})
		defer patch7.Reset()
		baseController.AddMecHost()
	})
}

func testUpdateMecHost(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestUpdateMecHost", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]string{
			"mechostIp":   ipAddress,
			"mechostName": "edgegallery",
			"zipCode":     "560048",
			"city":        "xian",
			"address":     "xian",
			"affinity":    "shenzhen",
			"userName":    "root1",
			"coordinates": "1,2",
			"vim":         "k8s",
			originKey:     originVal,
		})

		// Get Request
		mecHostRequest, _ := getHttpRequest(hostsPath, extraParams,
			packageName, "", "POST", requestBody)

		// Prepare Input
		mecHostInput := &context.BeegoInput{Context: &context.Context{Request: mecHostRequest}, RequestBody: requestBody}
		setParam(mecHostInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: mecHostInput,
			Request: mecHostRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test Add mec host
		instantiateController.UpdateMecHost()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Update MEC host failed")

		//case-2
		patch5 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return err
		})
		defer patch5.Reset()
		instantiateController.UpdateMecHost()
	})
}

func testGetMecHost(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestGetMecHost", func(t *testing.T) {

		// Get Request
		mecHostRequest, _ := getHttpRequest(hostsPath,
			extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		mecHostInput := &context.BeegoInput{Context: &context.Context{Request: mecHostRequest}}
		setParam(mecHostInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: mecHostInput, Request: mecHostRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Test query
		queryController.GetMecHost()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 404, queryController.Ctx.ResponseWriter.Status, queryFailed)
		response := queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
		assert.Equal(t, "null", response.Body.String(), queryFailed)

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return errors.New("error")
		})
		defer patch1.Reset()

		queryController.GetMecHost()
		assert.Equal(t, 404, queryController.Ctx.ResponseWriter.Status, queryFailed)

	})
}

func testDeleteMecHost(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeleteMecHost", func(t *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest(hostsPath+"/1.1.1.1", extraParams,
			"file", "", deleteOper, []byte(""))

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest}}
		setParam(instantiateInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: instantiateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test instantiate
		instantiateController.DeleteMecHost()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 500, instantiateController.Ctx.ResponseWriter.Status,
			deleteMecHostSuccess)

		//case-2
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		instantiateController.DeleteMecHost()
		assert.NotEmpty(t, 400, instantiateController.Ctx.ResponseWriter.Status,
			"Failed to delete mec host")

		//case-3
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch2.Reset()
		patch5 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return err
		})
		defer patch5.Reset()
		instantiateController.DeleteMecHost()
		assert.NotEmpty(t, 400, instantiateController.Ctx.ResponseWriter.Status,
			"Failed to delete mec host")

		//case-4
		patch6 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch6.Reset()
		patch7 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return nil
		})
		defer patch7.Reset()
		patch8 := gomonkey.ApplyFunc(util.ValidateUserName, func(_ string, _ string) (bool, error) {
			return false, err
		})
		defer patch8.Reset()
		instantiateBeegoController.Ctx.Request.Header.Set("name", "testKey")
		instantiateController.DeleteMecHost()
		assert.NotEmpty(t, 400, instantiateController.Ctx.ResponseWriter.Status,
			"username is invalid")
	})
}

func testErrorScenarios(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestErrorScenarios", func(t *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/hosts/1.1.1.1", extraParams,
			"file", "", deleteOper, []byte(""))

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest}}
		setParam(instantiateInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: instantiateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test handle logging for error
		instantiateController.HandleLoggingForError(ipAddress, 400, "failed to delete directory")

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, instantiateController.Ctx.ResponseWriter.Status,
			"HandleLoggingForError successful")

		// Test handle logging for error
		instantiateController.HandleLoggingForFailure(ipAddress, util.Forbidden)

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, instantiateController.Ctx.ResponseWriter.Status,
			handleLoggingFailure)

		// Test handle logging for error
		instantiateController.HandleLoggingForFailure(ipAddress, util.AccessTokenIsInvalid)

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, instantiateController.Ctx.ResponseWriter.Status,
			handleLoggingFailure)

		// Test handle logging for error
		instantiateController.HandleLoggingForFailure(ipAddress, "Failed to Instantiate")

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, instantiateController.Ctx.ResponseWriter.Status,
			handleLoggingFailure)

		// Test handle logging for error
		instantiateController.HandleLoggingForTokenFailure(ipAddress, util.Forbidden)

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, instantiateController.Ctx.ResponseWriter.Status,
			"Handle token logging failure is success")

		// Test handle logging for error
		instantiateController.HandleLoggingForTokenFailure(ipAddress, util.AccessTokenIsInvalid)

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, instantiateController.Ctx.ResponseWriter.Status,
			"Handle token logging failure is success")

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController1 := &controllers.ErrorController{Controller: instantiateBeegoController}

		instantiateController1.Error404()
	})
}

func testDeletePackageOnHost(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeletePackageOnHost", func(t *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/packages/"+
			packageId+hosts+ipAddress, extraParams,
			"file", "", deleteOper, []byte(""))

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest}}
		setParam(instantiateInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: instantiateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		err := errors.New("error")

		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), insertOrUpdateData,
			func(_ *MockDb, data interface{}, cols ...string) (error error) {
				return err
			})
		defer patch4.Reset()

		accessToken := createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

	})
}

func testDeletePackageOnHostV2(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeletePackageOnHost", func(t *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v2/packages/"+
			packageId+hosts+ipAddress, extraParams,
			"file", "", deleteOper, []byte(""))

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest}}
		setParam(instantiateInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: instantiateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test instantiate
		instantiateController.DeletePackageOnHost()

		// Check for success case wherein the status value will be default i.e. 0
		assert.NotEqual(t, instantiateController.Ctx.ResponseWriter.Status,
			deleteMecHostSuccess)

		err := errors.New("error")
		accessToken := createToken(tenantIdentifier)
		patch13 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), deleteTenantRecord, func(_ *controllers.LcmControllerV2, _, _ string) (error error) {
			return err
		})
		defer patch13.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackage()
		instantiateController.DeleteAppPackageHostRecord(hostIp, packageId, tenantId)

		accessToken = createToken(tenantIdentifier)
		patch15 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), "DeleteData", func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch15.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackage()
		var clientIp2 string
		instantiateController.DelAppPkgRecords(clientIp2, packageId, tenantId, hostIp)

		accessToken = createToken(tenantIdentifier)
		patch12 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "DeleteAppPackageHostRecord",
			func(_ *controllers.LcmControllerV2, _, _, _ string) (error error) {
				return err
			})
		defer patch12.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackage()
		instantiateController.DelAppPkgRecords(clientIp2, packageId, tenantId, hostIp)

		accessToken = createToken(tenantIdentifier)
		patch11 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch11.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackage()
		instantiateController.DelAppPkgRecords(clientIp2, packageId, tenantId, hostIp)

		accessToken = createToken(tenantIdentifier)
		patch10 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "DelAppPkgRecords", func(_ *controllers.LcmControllerV2, _, _, _, _ string) error {
			return err
		})
		defer patch10.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackageOnHost()

		accessToken = createToken(tenantIdentifier)
		patch9 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), getVim, func(_ *controllers.LcmControllerV2, _ string, _ string) (string, error) {
			return "nil", err
		})
		defer patch9.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackageOnHost()
		var clientIp1 string
		instantiateController.GetVimAndHostIpFromPkgHostRec(clientIp1, packageId, tenantId, hostIp)

		accessToken = createToken(tenantIdentifier)
		patch14 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch14.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackage()
		var appPkgId string
		//clientIp := "172.1.1.1"
		instantiateController.GetAppPackageHostRecord(hostIp, appPkgId, tenantId, clientIp)
		accessToken = createToken(tenantIdentifier)

		patch8 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetAppPackageHostRecord", func(_ *controllers.LcmControllerV2, hostIp, appPkgId, tenantId, clientIp string) (*models.AppPackageHostRecord, error) {
			return nil, err
		})
		defer patch8.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackageOnHost()
		instantiateController.GetVimAndHostIpFromPkgHostRec(clientIp1, packageId, tenantId, hostIp)

		accessToken = createToken(tenantIdentifier)
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetAppPackageRecord", func(_ *controllers.LcmControllerV2, appPkgId string, tenantId string, clientIp string) (*models.AppPackageRecord, error) {
			return nil, err
		})
		defer patch7.Reset()

		patch16 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch16.Reset()

		patch17 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return err
		})
		defer patch17.Reset()

		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackageOnHost()
		instantiateController.GetVimAndHostIpFromPkgHostRec(clientIp1, packageId, tenantId, hostIp)

		accessToken = createToken(tenantIdentifier)
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetVimAndHostIpFromPkgHostRec", func(_ *controllers.LcmControllerV2, clientIp, packageId, tenantId, hostIp string) (string, string, string, error) {
			return "123", "", "", err
		})
		defer patch6.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackageOnHost()

		accessToken = createToken(tenantIdentifier)
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetUrlHostIP", func(_ *controllers.LcmControllerV2, clientIp string) (string, error) {
			return "", err
		})
		defer patch5.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackageOnHost()
		instantiateController.GetInputParametersForDelPkgOnHost(clientIp)

		patch20 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return err
		})
		defer patch20.Reset()
		_, _, _, result := instantiateController.GetInputParametersForDelPkgOnHost(clientIp)
		assert.NotEmpty(t, result, "failed to get input parameters")

		patch21 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return nil
		})
		defer patch21.Reset()
		accessToken = createToken(tenantIdentifier)
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetUrlPackageId", func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch4.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackageOnHost()
		instantiateController.GetInputParametersForDelPkgOnHost(clientIp)

		accessToken = createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), getTenantId, func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch3.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackageOnHost()
		instantiateController.GetInputParametersForDelPkgOnHost(clientIp)

		accessToken = createToken(tenantIdentifier)
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetInputParametersForDelPkgOnHost", func(_ *controllers.LcmControllerV2, _ string) (string, string, string, error) {
			return "123", "bKey", "", err
		})
		defer patch2.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackageOnHost()

		accessToken = createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), getClientIpAndValidateAccessToken,
			func(_ *controllers.LcmControllerV2, _ string, _ []string, _ string) (clientIp string, bKey []byte,
				accessToken string, error error) {
				return "123", bKey, "", err
			})
		defer patch1.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DeletePackageOnHost()
	})
}

func testDeletePackage(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeletePackage", func(t *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest(tenantsPath+
			tenantIdentifier+directory+
			packageId+hosts+ipAddress, extraParams,
			"file", "", deleteOper, []byte(""))

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest}}
		setParam(instantiateInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: instantiateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		err := errors.New("error")

		accessToken := createToken(tenantIdentifier)
		patch9 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch9.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

	})
}

func testDeletePackageV2(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeletePackage", func(t *testing.T) {

		// POST Request
		instantiateRequest2, _ := getHttpRequest(tenantsPathV2+
			tenantIdentifier+directory+
			packageId+hosts+ipAddress, extraParams,
			"file", "", deleteOper, []byte(""))

		// Prepare Input
		instantiateInput2 := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest2}}
		setParam(instantiateInput2)

		// Prepare beego controller
		instantiateBeegoControllerV2 := beego.Controller{Ctx: &context.Context{Input: instantiateInput2,
			Request: instantiateRequest2, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoControllerV2}}

		patch2 := gomonkey.ApplyFunc(os.Open, func(_ string) (*os.File, error) {
			return nil, nil
		})
		defer patch2.Reset()

		// Test instantiate
		instantiateController2.DeletePackage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 500, instantiateController2.Ctx.ResponseWriter.Status,
			deleteMecHostSuccess)

		err := errors.New("error")

		accessToken := createToken(tenantIdentifier)
		patch8 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController2), deleteTenantRecord, func(_ *controllers.LcmControllerV2, _, _ string) (error error) {
			return err
		})
		defer patch8.Reset()
		// Test upload package
		instantiateBeegoControllerV2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController2.DeletePackage()
		//clientIp := "172.1.1.1"
		instantiateController2.DeleteAppPkgRecords(packageId, tenantId, clientIp)

		accessToken = createToken(tenantIdentifier)
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController2), "DeleteAppPackageRecord", func(_ *controllers.LcmControllerV2, _ string, _ string) (error error) {
			return err
		})
		defer patch7.Reset()
		// Test upload package
		instantiateBeegoControllerV2.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		instantiateController2.DeletePackage()
		//instantiateController2.DeleteAppPkgRecords(packageId, tenantId, clientIp)

		accessToken = createToken(tenantIdentifier)
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController2.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch6.Reset()
		// Test upload package
		instantiateBeegoControllerV2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController2.DeletePackage()

		instantiateController2.DeleteAppPkgRecords(packageId, tenantId, clientIp)

		accessToken = createToken(tenantIdentifier)
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController2), "DeleteAppPkgRecords", func(_ *controllers.LcmControllerV2, _, _, _ string) (error error) {
			return err
		})
		defer patch5.Reset()
		// Test upload package
		instantiateBeegoControllerV2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController2.DeletePackage()

		accessToken = createToken(tenantIdentifier)
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController2), "ProcessDeletePackage", func(_ *controllers.LcmControllerV2, _, _, _, _ string) error {
			return err
		})
		defer patch4.Reset()
		// Test upload package
		instantiateBeegoControllerV2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController2.DeletePackage()

		accessToken = createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController2), "GetUrlPackageId", func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch3.Reset()
		// Test upload package
		instantiateBeegoControllerV2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController2.DeletePackage()

		accessToken = createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController2), getTenantId, func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch1.Reset()
		// Test upload package
		instantiateBeegoControllerV2.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController2.DeletePackage()

	})
}

func testDistributePackage(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDistributePackage", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string][]string{
			hostIpKey: {ipAddress},
		})
		// Get Request
		url := tenantsPath + tenantIdentifier + packages + packageId
		distributePkgRequest, _ := getHttpRequest(url, extraParams,
			packageName, "", "POST", []byte(""))

		// Prepare Input
		distributePkgInput := &context.BeegoInput{Context: &context.Context{Request: distributePkgRequest}, RequestBody: requestBody}

		setParam(distributePkgInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: distributePkgInput,
			Request: distributePkgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}
		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, distributePackageFailed)

		err := errors.New("error")

		accessToken := createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch3.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetUrlPackageId", func(_ *controllers.LcmController, _ string) (string, error) {
			return "", err
		})
		defer patch5.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		//instantiateController.DistributePackage()

		accessToken = createToken(tenantIdentifier)
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), getTenantId, func(_ *controllers.LcmController, _ string) (string, error) {
			return "", err
		})
		defer patch4.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)

		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
	})
}

func testDistributePackageV2(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDistributePackage", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string][]string{
			hostIpKey: {ipAddress},
		})
		// Get Request
		url := tenantsPath + tenantIdentifier + packages + packageId
		distributePkgRequest, _ := getHttpRequest(url, extraParams,
			packageName, "", "POST", []byte(""))

		// Prepare Input
		distributePkgInput := &context.BeegoInput{Context: &context.Context{Request: distributePkgRequest}, RequestBody: requestBody}

		setParam(distributePkgInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: distributePkgInput,
			Request: distributePkgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test instantiate
		instantiateController.DistributePackage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, distributePackageFailed)

		err := errors.New("error")

		accessToken := createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "ProcessUploadPackage", func(_ *controllers.LcmControllerV2, _ models.DistributeRequest,
			_, _, _, _ string) (error error) {
			return err
		})
		defer patch1.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DistributePackage()

		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, distributePackageFailed)

		accessToken = createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch3.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DistributePackage()

		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, distributePackageFailed)

		accessToken = createToken(tenantIdentifier)
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetUrlPackageId", func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch5.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DistributePackage()
		clientIp := "172.1.2.3"
		var req models.DistributeRequest
		instantiateController.ValidateDistributeInputParameters(clientIp, req)

		accessToken = createToken(tenantIdentifier)
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "ValidateDistributeInputParameters",
			func(_ *controllers.LcmControllerV2, _ string, _ models.DistributeRequest) (packageId string, error error) {
				return "", err
			})
		defer patch2.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DistributePackage()

		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, distributePackageFailed)

	})
}

func testDistributionStatus(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDistributionStatus", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string][]string{
			hostIpKey: {ipAddress},
		})
		// Get Request
		url := tenantsPath + tenantIdentifier + packages + packageId
		distributePkgRequest, _ := getHttpRequest(url, extraParams,
			packageName, "", "POST", []byte(""))

		// Prepare Input
		distributePkgInput := &context.BeegoInput{Context: &context.Context{Request: distributePkgRequest}, RequestBody: requestBody}

		setParam(distributePkgInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: distributePkgInput,
			Request: distributePkgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, distributePackageFailed)

		accessToken := createToken(tenantIdentifier)

		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), "QueryTable", func(_ *MockDb, _ string, _ interface{}, _ string, _ ...interface{}) (num int64, err error) {
			return 0, nil
		})
		defer patch1.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
	})
}

func testDistributionStatusV2(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDistributionStatus", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string][]string{
			hostIpKey: {ipAddress},
		})
		// Get Request
		url := tenantsPathV2 + tenantIdentifier + packages + packageId
		distributePkgRequest, _ := getHttpRequest(url, extraParams,
			packageName, "", "POST", []byte(""))

		// Prepare Input
		distributePkgInput := &context.BeegoInput{Context: &context.Context{Request: distributePkgRequest}, RequestBody: requestBody}

		setParam(distributePkgInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: distributePkgInput,
			Request: distributePkgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test instantiate
		instantiateController.DistributionStatus()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, distributePackageFailed)

		err := errors.New("error")
		accessToken := createToken(tenantIdentifier)

		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), "QueryTable", func(_ *MockDb, _ string, _ interface{}, _ string, _ ...interface{}) (num int64, err error) {
			return 0, nil
		})
		defer patch1.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DistributionStatus()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

		accessToken = createToken(tenantIdentifier)
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetUrlPackageId", func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err
		})
		defer patch5.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DistributionStatus()
		//clientIp := "172.1.1.1"
		instantiateController.GetInputParametersForDistributionStatus(clientIp)

		accessToken = createToken(tenantIdentifier)
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetInputParametersForDistributionStatus",
			func(_ *controllers.LcmControllerV2, _ string) (tenantId string, packageId string, error error) {
				return "", "", nil
			})
		defer patch2.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DistributionStatus()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

		accessToken = createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), getClientIpAndIsPermitted,
			func(_ *controllers.LcmControllerV2, _ string) (clientIp string, bkey []uint8, _, _ string, error error) {
				return "", bkey, "_", "_", err
			})
		defer patch3.Reset()
		// Test upload package
		instantiateBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
		instantiateController.DistributionStatus()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, instantiateController.Ctx.ResponseWriter.Status, uploadPackageFailed)

	})
}

func testUpload(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestConfigUpload", func(_ *testing.T) {
		err1 := errors.New("error")
		// Get Request
		uploadRequest, _ := getHttpRequest(configuration_request, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		uploadInput := &context.BeegoInput{Context: &context.Context{Request: uploadRequest}}
		setParam(uploadInput)

		// Prepare beego controller
		uploadBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadInput, Request: uploadRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		uploadController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoController}}

		// Check for success case wherein the status value will be default i.e. 0
		//		assert.Equal(t, 0, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(uploadController.Db), insertOrUpdateData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err1
		})
		defer patch4.Reset()

		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(uploadController.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err1
		})
		defer patch3.Reset()

	})
}

func testUploadV2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestConfigUploadV2", func(_ *testing.T) {

		// Get Request
		uploadRequest, _ := getHttpRequest(uploadConfigRequestV2, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		uploadInput := &context.BeegoInput{Context: &context.Context{Request: uploadRequest}}
		setParam(uploadInput)

		// Prepare beego controller
		uploadBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadInput, Request: uploadRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		uploadController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoController}}

		// Test instantiate
		uploadController.UploadConfigV2()

		assert.Equal(t, 200, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")

		// Get Request
		validParams := map[string]string{
			"hostIp":    "1.1.1.x",
			"appName":   "postioning-service",
			"packageId": "e261211d80d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98",
			"appId":     "e261211d80d04cb6aed00e5cd1f2cd11",
		}
		uploadRequest, _ = getHttpRequest(uploadConfigRequestV2, validParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		uploadInput = &context.BeegoInput{Context: &context.Context{Request: uploadRequest}}
		setParam(uploadInput)

		// Test instantiate
		uploadController.UploadConfigV2()

		assert.Equal(t, 200, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")
		err1 := errors.New("error")

		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(uploadController), "GetHostIP", func(_ *controllers.LcmControllerV2, _ string) (string, error) {
			return "", err1
		})
		defer patch2.Reset()
		// Test upload packages
		uploadController.UploadConfigV2()
		assert.Equal(t, 200, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")

		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(uploadController), "GetInputParametersForUploadCfg", func(_ *controllers.LcmControllerV2, _ string) (hostIp string,
			vim string, file multipart.File, err error) {
			return "", "nil", file, err1
		})
		defer patch1.Reset()
		// Test upload packages
		uploadController.UploadConfigV2()
		assert.Equal(t, 200, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")

	})
}

func testRemoval(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {
	t.Run("TestConfigRemoval", func(_ *testing.T) {
		// Get Request
		removeRequest, _ := getHttpRequest(configuration_request, extraParams,
			configfile, path, deleteOper, []byte(""))

		// Prepare Input
		removeInput := &context.BeegoInput{Context: &context.Context{Request: removeRequest}}
		setParam(removeInput)

		// Prepare beego controller
		removeBeegoController := beego.Controller{Ctx: &context.Context{Input: removeInput, Request: removeRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		removeController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: removeBeegoController}}

		err := errors.New("error")
		accessToken := createToken(tenantIdentifier)
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(removeController.Db), insertOrUpdateData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch3.Reset()
		// Test upload package
		removeBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(removeController), getVim, func(_ *controllers.LcmController, _ string, _ string, _ string) (string, error) {
			return "", err
		})
		defer patch7.Reset()
		removeBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(removeController.Db), readData, func(_ *MockDb, _ interface{}, _ ...string) (error error) {
			return err
		})
		defer patch6.Reset()
		// Test upload package
		removeBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		removeBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		accessToken = createToken(tenantIdentifier)
		removeBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)
	})
}

func testRemovalV2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {
	t.Run("TestConfigRemovalV2", func(_ *testing.T) {

		// Get Request
		removeRequestv2, _ := getHttpRequest(uploadConfigRequestV2, extraParams,
			configfile, path, deleteOper, []byte(""))

		// Prepare Input
		removeInputv2 := &context.BeegoInput{Context: &context.Context{Request: removeRequestv2}}
		setParam(removeInputv2)

		// Prepare beego controller
		removeBeegoControllerv2 := beego.Controller{Ctx: &context.Context{Input: removeInputv2, Request: removeRequestv2,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		removeControllerv2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: removeBeegoControllerv2}}

		// Test instantiate
		removeControllerv2.RemoveConfigV2()

		//case-2:
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		removeControllerv2.RemoveConfigV2()

		//case-3:
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyFunc(util.ValidateAccessToken,
			func(_ string, _ []string, _ string) error {
				return err
			})
		defer patch3.Reset()
		removeControllerv2.RemoveConfigV2()

		//case-4:
		patch4 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch4.Reset()
		patch6 := gomonkey.ApplyFunc(util.ValidateAccessToken,
			func(accessToken string, allowedRoles []string, _ string) error {
				return nil
			})
		defer patch6.Reset()
		/*patch5 := gomonkey.ApplyMethod(reflect.TypeOf(removeControllerv2), "GetInputParametersForRemoveCfg",
			func(_ *controllers.LcmControllerV2, _ string) (_ string, _ string, _ *models.MecHost, error error) {
				return username, "", nil, err
			})
		defer patch5.Reset()*/
		patch5 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, err
		})
		defer patch5.Reset()
		removeControllerv2.RemoveConfigV2()

		//case-5
		patch7 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch7.Reset()
		patch8 := gomonkey.ApplyFunc(util.ValidateAccessToken,
			func(accessToken string, allowedRoles []string, _ string) error {
				return nil
			})
		defer patch8.Reset()
		patch9 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, nil
		})
		defer patch9.Reset()
		patch10 := gomonkey.ApplyMethod(reflect.TypeOf(removeControllerv2.Db), "InsertOrUpdateData",
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch10.Reset()
		removeControllerv2.RemoveConfigV2()

	})
}

func setParam(ctx *context.BeegoInput) {
	ctx.SetParam(tenantId, tenantIdentifier)
	ctx.SetParam(":appInstanceId", appInstanceIdentifier)
	ctx.SetParam(":packageId", packageId)
	ctx.SetParam(":hostIp", ipAddress)
}
