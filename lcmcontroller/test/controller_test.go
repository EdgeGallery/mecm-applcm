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
		"hostIp":    "1.1.1.1",
		"packageId": packageId,
		"appName":   appName,
	}

	testDb := &mockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords: make(map[string]models.TenantInfoRecord),
		appPackageRecords: make(map[string]models.AppPackageRecord),
		mecHostRecords: make(map[string]models.MecHost),
		appPackageHostRecords: make(map[string]models.AppPackageHostRecord)}

	//Upload package
	testUploadPackage(t, extraParams, path, testDb)

	testAddMecHost(t, extraParams, path, testDb)

	//Distribute package
	testDistributePackage(t, extraParams, path, testDb)

	// Test instantiate
	testInstantiate(t, extraParams, path, testDb)

	// Test query
	testQuery(t, nil, "", testDb, "Success")

	// Test query
	testWorkloadEvents(t, nil, "", testDb, "Success")

	// Test terminate
	testTerminate(t, nil, "", testDb)

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
		"hostIp":  "1.1.1.1",
		"appName": appName,
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

	testAddMecHost(t, extraParams, path, testDb)

	// Test upload
	testUpload(t, extraParams, path, testDb)

	// Test removal
	testRemoval(t, extraParams, path, testDb)
}

func testQuery(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database, exOutput string) {

	t.Run("TestAppInstanceQuery", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/e921ce54-82c8-4532-b5c6-"+
			"8516cf75f7a6/app_instances/e921ce54-82c8-4532-b5c6-8516cf75f7a4", extraParams, "file", path, "GET", []byte(""))

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
	})
}

func testWorkloadEvents(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database,
	exOutput string) {

	t.Run("TestWorkloadEventsQuery", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/e921ce54-82c8-4532-b5c6-"+
			"8516cf75f7a6/app_instances/e921ce54-82c8-4532-b5c6-8516cf75f7a4/workload/events", extraParams, "file", path, "GET", []byte(""))

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
	})
}

func testTerminate(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {
	t.Run("TestAppInstanceTerminate", func(t *testing.T) {

		// Terminate Request
		terminateRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/e921ce54-82c8-4532-"+
			"b5c6-8516cf75f7a6/app_instances/e921ce54-82c8-4532-b5c6-8516cf75f7a4/terminate", extraParams, "file",
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
	})
}

func testInstantiate(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestAppInstanceInstantiate", func(t *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/e921ce54-82c8-"+
			"4532-b5c6-8516cf75f7a6/app_instances/e921ce54-82c8-4532-b5c6-8516cf75f7a4/instantiate", extraParams,
			"file", "", "POST", []byte(""))

		requestBody, _ := json.Marshal(map[string]string{
			"hostIp": "1.1.1.1",
			"packageId": "e261211d80d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98",
			"appName": "testApplication",
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
	})
}

func testUploadPackage(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestUploadPackage", func(t *testing.T) {

		// Get Request
		url := "https://edgegallery:8094/lcmcontroller/v1/tenants/" + tenantIdentifier + "/packages"
		uploadPkgRequest, _ := getHttpRequest(url, extraParams,
			"package", path, "POST", []byte(""))

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

		// Test instantiate
		instantiateController.UploadPackage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Upload package failed")
	})
}

func testAddMecHost(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestAddMecHost", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]string{
			"mechostIp": "1.1.1.1",
			"mechostName": "edgegallery3",
			"zipCode": "560036",
			"city": "bangalore",
			"address": "anadapura",
			"affinity": "karanataka",
			"userName": "ramasubba",
			"coordinates":"1,2",
			"vim": "k8s",
		})

		// Get Request
		mecHostRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/hosts", extraParams,
			"package", "", "POST", requestBody)

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

		// Test instantiate
		instantiateController.AddMecHost()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Add MEC host failed")
	})
}

func testDistributePackage(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestDistributePackage", func(t *testing.T) {

		/*requestBody := map[string][]string{
			"hostIp": []string{"1.1.1.1", "2.2.2.2"},
		}*/
		requestBody, _ := json.Marshal(map[string][]string{
			"hostIp": []string{"1.1.1.1"},
		})
		// Get Request
		url := "https://edgegallery:8094/lcmcontroller/v1/tenants/" + tenantIdentifier + "/packages" + packageId
		distributePkgRequest, _ := getHttpRequest(url, extraParams,
			"package", "", "POST", []byte(""))

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

func testUpload(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestConfigUpload", func(t *testing.T) {

		// Get Request
		uploadRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/configuration", extraParams,
			"configFile", path, "POST", []byte(""))

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
		assert.Equal(t, 0, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")
	})
}

func testRemoval(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {
	t.Run("TestConfigRemoval", func(t *testing.T) {
		// Get Request
		removeRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/configuration", extraParams,
			"configFile", path, "DELETE", []byte(""))

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
		assert.Equal(t, 0, removeController.Ctx.ResponseWriter.Status, "Config removal failed")
	})
}

func setParam(ctx *context.BeegoInput) {
	ctx.SetParam(":tenantId", tenantIdentifier)
	ctx.SetParam(":appInstanceId", appInstanceIdentifier)
	ctx.SetParam(":packageId", packageId)
}
