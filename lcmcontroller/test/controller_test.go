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
	"fmt"
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
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

var (
	filePermission os.FileMode = 0750
	directory                  = "/packages/"
	hostIpAddress              = fmt.Sprintf(ipAddFormatter, rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal),
		rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal))
	tenantIdentifier      = "e921ce54-82c8-4532-b5c6-8516cf75f7a6"
	appInstanceIdentifier = "e921ce54-82c8-4532-b5c6-8516cf75f7a4"
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
		"hostIp":    hostIpAddress,
		"packageId": "51e5fe1053254a32bce87ebe9708c453",
		"appName":   appName,
	}

	testDb := &mockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords: make(map[string]models.TenantInfoRecord)}

	// Test instantiate
	testInstantiate(t, extraParams, path, testDb)

	// Test query
	testQuery(t, nil, "", testDb, "Success")

	// Test query
	testPodDescribe(t, nil, "", testDb, "Success")

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
		"hostIp":  hostIpAddress,
		"appName": appName,
	}

	var c *beego.Controller
	patch1 := gomonkey.ApplyMethod(reflect.TypeOf(c), "ServeJSON", func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch1.Reset()

	// Test upload
	testUpload(t, extraParams, path)

	// Test removal
	testRemoval(t, extraParams, path)
}

func testQuery(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database, exOutput string) {

	t.Run("TestAppInstanceQuery", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/e921ce54-82c8-4532-b5c6-"+
			"8516cf75f7a6/app_instances/e921ce54-82c8-4532-b5c6-8516cf75f7a4", extraParams, "file", path, "GET")

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmController{Db: testDb, Controller: queryBeegoController}

		// Test query
		queryController.Query()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, queryFailed)
		response := queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
		assert.Equal(t, exOutput, response.Body.String(), queryFailed)
	})
}

func testPodDescribe(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database, exOutput string) {

	t.Run("TestPodDescribeQuery", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/e921ce54-82c8-4532-b5c6-"+
			"8516cf75f7a6/app_instances/e921ce54-82c8-4532-b5c6-8516cf75f7a4/pods/desc", extraParams, "file", path, "GET")

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmController{Db: testDb, Controller: queryBeegoController}

		// Test query
		queryController.GetPodDescription()

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
			path, "POST")

		// Prepare Input
		terminateInput := &context.BeegoInput{Context: &context.Context{Request: terminateRequest}}
		setParam(terminateInput)

		// Prepare beego controller
		terminateBeegoController := beego.Controller{Ctx: &context.Context{Input: terminateInput,
			Request: terminateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		terminateController := &controllers.LcmController{Db: testDb, Controller: terminateBeegoController}

		// Test query
		terminateController.Terminate()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, terminateController.Ctx.ResponseWriter.Status, "Terminate failed")
	})
}

func testInstantiate(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestAppInstanceInstantiate", func(t *testing.T) {

		// Get Request
		instantiateRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/e921ce54-82c8-"+
			"4532-b5c6-8516cf75f7a6/app_instances/e921ce54-82c8-4532-b5c6-8516cf75f7a4/instantiate", extraParams,
			"file", path, "POST")

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest}}
		setParam(instantiateInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: instantiateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmController{Db: testDb, Controller: instantiateBeegoController}

		// Test instantiate
		instantiateController.Instantiate()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, instantiateController.Ctx.ResponseWriter.Status, "Instantiation failed")
	})
}

func testUpload(t *testing.T, extraParams map[string]string, path string) {

	t.Run("TestConfigUpload", func(t *testing.T) {

		// Get Request
		uploadRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/configuration", extraParams,
			"configFile", path, "POST")

		// Prepare Input
		uploadInput := &context.BeegoInput{Context: &context.Context{Request: uploadRequest}}
		setParam(uploadInput)

		// Prepare beego controller
		uploadBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadInput, Request: uploadRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		uploadController := &controllers.LcmController{Db: &mockDb{}, Controller: uploadBeegoController}

		// Test instantiate
		uploadController.UploadConfig()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")
	})
}

func testRemoval(t *testing.T, extraParams map[string]string, path string) {
	t.Run("TestConfigRemoval", func(t *testing.T) {
		// Get Request
		removeRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/configuration", extraParams,
			"configFile", path, "DELETE")

		// Prepare Input
		removeInput := &context.BeegoInput{Context: &context.Context{Request: removeRequest}}
		setParam(removeInput)

		// Prepare beego controller
		removeBeegoController := beego.Controller{Ctx: &context.Context{Input: removeInput, Request: removeRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		removeController := &controllers.LcmController{Db: &mockDb{}, Controller: removeBeegoController}

		// Test instantiate
		removeController.RemoveConfig()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, removeController.Ctx.ResponseWriter.Status, "Config removal failed")
	})
}

func setParam(ctx *context.BeegoInput) {
	ctx.SetParam(":tenantId", tenantIdentifier)
	ctx.SetParam(":appInstanceId", appInstanceIdentifier)
}
