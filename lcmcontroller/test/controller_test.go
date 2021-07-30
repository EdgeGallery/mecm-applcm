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
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

var (
	filePermission os.FileMode = 0750
	directory                  = "/packages/"
	tenantIdentifier      = "e921ce54-82c8-4532-b5c6-8516cf75f7a6"
	appInstanceIdentifier = "e921ce54-82c8-4532-b5c6-8516cf75f7a4"
	packageId             = "e261211d80d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98"
	appName               = "postioning-service"
	queryFailed           = "Query failed"
	handleLoggingFailure  = "Handle logging failure is success"
	deleteMecHostSuccess  = "Delete mec host is successful"
	deleteOper            = "DELETE"
	hostsPath             = "https://edgegallery:8094/lcmcontroller/v1/hosts"
	packageName           = "package"
	packages              = "/packages"
	tenantsPath           = "https://edgegallery:8094/lcmcontroller/v1/tenants/"
	appUrlPath            = tenantsPath + "e921ce54-82c8-4532-b5c6-8516cf75f7a6/app_instances/"
	appUrlPathId          = tenantsPath + "e921ce54-82c8-4532-b5c6-8516cf75f7a6/app_instances/" + appInstanceIdentifier
	originKey             = "origin"
	originVal             = "MEPM"
	appNameKey            = "appName"
	packageIdKey          = "packageId"
	hostIpKey             = "hostIp"
        sync_deleted_request  = "https://edgegallery:8094/lcmcontroller/v1/tenants/hosts/sync_deleted"
        configuration_request = "https://edgegallery:8094/lcmcontroller/v1/configuration"
        configfile            = "configFile"
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
	path := baseDir + "/positioning_with_mepagent_new.csar"
	controllers.PackageFolderPath = baseDir + directory
	_ = os.Mkdir(baseDir+directory, filePermission)
	extraParams := map[string]string{
		hostIpKey:    ipAddress,
		packageIdKey: packageId,
		appNameKey:   appName,
		originKey: originVal,
	}

	testDb := &mockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords: make(map[string]models.TenantInfoRecord),
		appPackageRecords: make(map[string]models.AppPackageRecord),
		mecHostRecords: make(map[string]models.MecHost),
		appPackageHostRecords: make(map[string]models.AppPackageHostRecord)}

	//Upload package
	testUploadPackage(t, extraParams, path, testDb)

	// Test Add mec host
	testAddMecHost(t, extraParams, testDb)

	// Test update mec host
	testUpdateMecHost(t, extraParams, testDb)

	// Test get mec host
	testGetMecHost(t, nil, "", testDb)

	// Test sync updated mec host record
	testSyncUpdatedMecHostRec(t, nil, "", testDb)

	// Test Distribute package
	testDistributePackage(t, extraParams, testDb)

	// Test Distribution status
	testDistributionStatus(t, extraParams, testDb)

	// Test instantiate
	testInstantiate(t, extraParams, testDb)

	// Test create image
	testCreateImage(t, extraParams, testDb)

	// Test get image
	testGetImage(t, extraParams, testDb)

	// Test get image file
	testGetImageFile(t, extraParams, testDb)

	// Test delete image file
	testDeleteImage(t, extraParams, testDb)

	// Test get app instance
	testGetAppInstance(t, nil, "", testDb)

	// Test sync updated app instances record
	testSyncUpdatedAppInstRec(t, nil, "", testDb)

	// Test sync updated app package updated record
	testSynchronizeAppPackageUpdatedRecord(t, nil, "", testDb)

	// Test sync stale app package updated record
	testSynchronizeAppPackageStaleRecord(t, nil, "", testDb)

	// Test query
	testQuery(t, nil, "", testDb, "Success")

	// Test workload events
	testWorkloadEvents(t, nil, "", testDb, "Success")

	// Test terminate
	testTerminate(t, nil, "", testDb)

	//Test sync stale app information records
	testSynchronizeStaleRecord(t, nil, "", testDb)

	// Test sync updated mec host record
	testSyncMecHostStaleRecord(t, nil, "", testDb)

	// Test instantiate
	testInstantiate(t, extraParams, testDb)

	// Test delete package on host
	testDeletePackageOnHost(t, extraParams, testDb)

	// Test delete package
	testDeletePackage(t, extraParams, testDb)

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
	testDb := &mockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords: make(map[string]models.TenantInfoRecord),
		appPackageRecords: make(map[string]models.AppPackageRecord),
		mecHostRecords: make(map[string]models.MecHost),
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

	// Test removal
	testRemoval(t, extraParams, path, testDb)
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

		// Test query
		queryController.Query()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		response := queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
		assert.Equal(t, exOutput, response.Body.String(), queryFailed)

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

	})
}

func testSyncUpdatedAppInstRec(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSyncUpdatedAppInstRec", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(appUrlPath + "sync_updated", extraParams, "file", path, "GET", []byte(""))

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

		// Test query
		queryController.SynchronizeUpdatedRecord()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//for v2

		// Get Request
		queryRequestv2, _ := getHttpRequest(appUrlPath + "sync_updated", extraParams, "file", path, "GET", []byte(""))

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
		queryControllerv2.SynchronizeUpdatedRecordV2()
	})
}

func testSynchronizeAppPackageStaleRecord(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSynchronizeAppPackageStaleRecord", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(tenantsPath + tenantIdentifier + "/packages/sync_deleted", extraParams, "file", path, "GET", []byte(""))

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

		// Test query
		queryController.SynchronizeAppPackageStaleRecord()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//Newly added test cases for failure case checking

		//tenantid empty failure case
		queryBeegoController.Ctx.Input.SetParam(":tenantId","")
		queryController.SynchronizeAppPackageStaleRecord()
		assert.Equal(t, 400, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//client ip empty failure case
		queryBeegoController.Ctx.Request.Header.Set("X-Forwarded-For","")
		queryController.SynchronizeAppPackageStaleRecord()
		assert.Equal(t, 400, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//Access_token failure case
		s := string([]byte{1})
		queryBeegoController.Ctx.Request.Header.Set(util.AccessToken,s)
		queryController.SynchronizeAppPackageStaleRecord()
		assert.Equal(t, 400, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//for v2

		// Get Request
		queryRequestv2, _ := getHttpRequest(tenantsPath + tenantIdentifier + "/packages/sync_deleted", extraParams, "file", path, "GET", []byte(""))

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
		queryControllerv2.SynchronizeAppPackageStaleRecordV2()

	})
}


func testSynchronizeAppPackageUpdatedRecord(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSynchronizeAppPackageUpdatedRecord", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(tenantsPath + tenantIdentifier +  "/packages/sync_updated", extraParams,
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

		// Test query
		queryController.SynchronizeAppPackageUpdatedRecord()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
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

		// Test query
		queryController.SynchronizeStaleRecord()

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
		queryControllerv2.SynchronizeStaleRecordV2()
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
		queryRequest, _ := getHttpRequest(appUrlPathId + "workload/events", extraParams, "file", path, "GET", []byte(""))

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

		// Test query
		queryController.GetWorkloadDescription()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		response := queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
		assert.Equal(t, exOutput, response.Body.String(), queryFailed)

		//for v2

		// Get Request
		queryRequestv2, _ := getHttpRequest(appUrlPathId + "workload/events", extraParams, "file", path, "GET", []byte(""))

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
		queryControllerv2.GetWorkloadDescriptionV2()
	})
}

func testTerminate(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {
	t.Run("TestAppInstanceTerminate", func(t *testing.T) {

		// Terminate Request
		terminateRequest, _ := getHttpRequest(appUrlPathId + "terminate", extraParams, "file",
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

		// Test query
		terminateController.Terminate()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, terminateController.Ctx.ResponseWriter.Status, "Terminate failed")

		//for v2

		// Terminate Request
		terminateRequestv2, _ := getHttpRequest(appUrlPathId + "terminate", extraParams, "file",
			path, "POST", []byte(""))

		// Prepare Input
		terminateInputv2 := &context.BeegoInput{Context: &context.Context{Request: terminateRequestv2}}
		setParam(terminateInputv2)

		// Prepare beego controller
		terminateBeegoControllerv2 := beego.Controller{Ctx: &context.Context{Input: terminateInputv2,
			Request: terminateRequestv2, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		terminateControllerv2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: terminateBeegoControllerv2}}

		// Test query
		terminateControllerv2.TerminateV2()
	})
}

func testBatchTerminate(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestBatchTerminate", func(t *testing.T) {
		// POST Request
		batchTerminateRequest, _ := getHttpRequest(appUrlPath + "batchTerminate", extraParams,
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
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Batch terminate failed")
	})
}

func testInstantiate(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestAppInstanceInstantiate", func(t *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest(appUrlPath + "instantiate", extraParams,
			"file", "", "POST", []byte(""))

		requestBody, _ := json.Marshal(map[string]string{
			hostIpKey: ipAddress,
			packageIdKey: packageId,
			appNameKey: "testApplication",
			originKey: originVal,
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

		// Test instantiate
		instantiateController.Instantiate()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Instantiation failed")

		//for v2

		// POST Request
		instantiateRequestv2, _ := getHttpRequest(appUrlPath + "instantiate", extraParams,
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

	})
}

func testCreateImage(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestCreateImage", func(t *testing.T) {

		// POST Request
		createImageRequest, _ := getHttpRequest(appUrlPath + "images", extraParams,
			"file", "", "POST", []byte(""))

		requestBody, _ := json.Marshal(map[string]string{
			hostIpKey: ipAddress,
			packageIdKey: packageId,
			originKey: originVal,
		})

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: createImageRequest}, RequestBody: requestBody}
		setParam(instantiateInput)

		// Prepare beego controller
		createImageBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: createImageRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.ImageController{controllers.BaseController{Db: testDb,
			Controller: createImageBeegoController}}

		// Test instantiate
		instantiateController.CreateImage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Create image failed")
	})
}

func testGetImage(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestGetImage", func(t *testing.T) {

		// POST Request
		getImageRequest, _ := getHttpRequest(appUrlPath + "images/1", extraParams,
			"file", "", "GET", []byte(""))

		requestBody, _ := json.Marshal(map[string]string{
			hostIpKey: ipAddress,
			packageIdKey: packageId,
			originKey: originVal,
		})

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: getImageRequest}, RequestBody: requestBody}
		setParam(instantiateInput)

		// Prepare beego controller
		getImageBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: getImageRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		getImageController := &controllers.ImageController{controllers.BaseController{Db: testDb,
			Controller: getImageBeegoController}}

		// Test instantiate
		getImageController.GetImage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, getImageController.Ctx.ResponseWriter.Status, "Get image failed")
	})
}

func testGetImageFile(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestGetImageFile", func(t *testing.T) {

		// POST Request
		getImageFileRequest, _ := getHttpRequest(appUrlPath + "images/1/file", extraParams,
			"file", "", "GET", []byte(""))

		requestBody, _ := json.Marshal(map[string]string{
			hostIpKey: ipAddress,
			packageIdKey: packageId,
			originKey: originVal,
		})

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: getImageFileRequest}, RequestBody: requestBody}
		setParam(instantiateInput)
		instantiateOutput := &context.BeegoOutput{Context: &context.Context{Request: getImageFileRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}}}

		// Prepare beego controller
		getImageFileBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput, Output: instantiateOutput,
			Request: getImageFileRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		getImageFileController := &controllers.ImageController{controllers.BaseController{Db: testDb,
			Controller: getImageFileBeegoController}}

		// Test instantiate
		getImageFileController.GetImageFile()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 500, getImageFileController.Ctx.ResponseWriter.Status, "Get image file failed")
	})
}


func testDeleteImage(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeleteImage", func(t *testing.T) {

		// POST Request
		delImageRequest, _ := getHttpRequest(appUrlPath + "images/1", extraParams,
			"file", "", "GET", []byte(""))

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: delImageRequest}, RequestBody: []byte("")}
		setParam(instantiateInput)

		// Prepare beego controller
		delImageBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: delImageRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		delImageController := &controllers.ImageController{controllers.BaseController{Db: testDb,
			Controller: delImageBeegoController}}

		// Test instantiate
		delImageController.DeleteImage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, delImageController.Ctx.ResponseWriter.Status, "Get image failed")
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

		// Test upload package
		instantiateController.UploadPackage()


		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Upload package failed")

		// Test Ratelimiter
		r := &util.RateLimiter{}
		rate, _ := limiter.NewRateFromFormatted("200-S")
		r.GeneralLimiter = limiter.New(memory.NewStore(), rate)
		util.RateLimit(r, instantiateController.Ctx)

		//for v2

		// Get Request
		uploadPkgRequestv2, _ := getHttpRequest(url, extraParams,
			packageName, path, "POST", []byte(""))

		// Prepare Input
		uploadPkgInputv2 := &context.BeegoInput{Context: &context.Context{Request: uploadPkgRequestv2}}
		setParam(uploadPkgInputv2)

		// Prepare beego controller
		instantiateBeegoControllerv2 := beego.Controller{Ctx: &context.Context{Input: uploadPkgInputv2,
			Request: uploadPkgRequestv2, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateControllerv2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoControllerv2}}

		instantiateControllerv2.UploadPackageV2()
		//assert.Equal(t, 401, instantiateControllerv2.Ctx.ResponseWriter.Status, "Upload package failed")


	})
}

func testAddMecHost(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestAddMecHost", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]string{
			"mechostIp": ipAddress,
			"mechostName": "edgegallery",
			"zipCode": "560048",
			"city": "xian",
			"address": "xian",
			"affinity": "shenzhen",
			"userName": "root",
			"coordinates":"1,2",
			originKey: originVal,
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
	})
}

func testUpdateMecHost(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestUpdateMecHost", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]string{
			"mechostIp": ipAddress,
			"mechostName": "edgegallery",
			"zipCode": "560048",
			"city": "xian",
			"address": "xian",
			"affinity": "shenzhen",
			"userName": "root1",
			"coordinates":"1,2",
			"vim": "k8s",
			originKey: originVal,
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
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		response := queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
		assert.Equal(t, "null", response.Body.String(), queryFailed)
	})
}

func testDeleteMecHost(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeleteMecHost", func(t *testing.T) {

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
		instantiateController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test instantiate
		instantiateController.DeleteMecHost()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status,
			deleteMecHostSuccess)
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
		instantiateRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/packages/" +
			 packageId + "/hosts/" + ipAddress, extraParams,
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

		// Test instantiate
		instantiateController.DeletePackageOnHost()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status,
			deleteMecHostSuccess)
	})
}

func testDeletePackage(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeletePackage", func(t *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest(tenantsPath +
			tenantIdentifier + "/packages/" +
			packageId + "/hosts/" + ipAddress, extraParams,
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

		// Test instantiate
		instantiateController.DeletePackage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status,
			deleteMecHostSuccess)
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

		// Test instantiate
		instantiateController.DistributePackage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Distribute package failed")
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

		// Test instantiate
		instantiateController.DistributionStatus()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Distribute package failed")
	})
}

func testUpload(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestConfigUpload", func(_ *testing.T) {

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

		// Test instantiate
		uploadController.UploadConfig()
		
		// Check for success case wherein the status value will be default i.e. 0
//		assert.Equal(t, 0, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")

		//for v2

		// Get Request
		uploadRequestv2, _ := getHttpRequest(configuration_request, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		uploadInputv2 := &context.BeegoInput{Context: &context.Context{Request: uploadRequest}}
		setParam(uploadInputv2)

		// Prepare beego controller
		uploadBeegoControllerv2 := beego.Controller{Ctx: &context.Context{Input: uploadInputv2, Request: uploadRequestv2,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		uploadControllerv2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoControllerv2}}

		// Test instantiate
		uploadControllerv2.UploadConfigV2()

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

		// Test instantiate
		removeController.RemoveConfig()

		// Check for success case wherein the status value will be default i.e. 0
//		assert.Equal(t, 0, removeController.Ctx.ResponseWriter.Status, "Config removal failed")

       //for v2

		// Get Request
		removeRequestv2, _ := getHttpRequest(configuration_request, extraParams,
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
	})
}

func setParam(ctx *context.BeegoInput) {
	ctx.SetParam(":tenantId", tenantIdentifier)
	ctx.SetParam(":appInstanceId", appInstanceIdentifier)
	ctx.SetParam(":packageId", packageId)
	ctx.SetParam(":hostIp", ipAddress)
}
