/*
 * Copyright 2021 Huawei Technologies Co., Ltd.
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
 *
 */

package test

import (
	"bytes"
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
func TestMep(t *testing.T) {

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
	controllers.PackageFolderPath = baseDir + directory
	_ = os.Mkdir(baseDir+directory, filePermission)
	testDb := &MockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords:         make(map[string]models.TenantInfoRecord),
		appPackageRecords:     make(map[string]models.AppPackageRecord),
		mecHostRecords:        make(map[string]models.MecHost),
		appPackageHostRecords: make(map[string]models.AppPackageHostRecord)}

	testServices(t, nil, "", testDb)

	testKongLog(t, nil, "", testDb)
}
func testServices(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("testServices", func(_ *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(tenantsPath+tenantIdentifier+"/mep/services", extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.MepController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Test query
		queryController.Services()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 500, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		//client ip empty failure case
		queryBeegoController.Ctx.Request.Header.Set("X-Forwarded-For","")
		queryController.Services()
		assert.Equal(t, 500, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)
	})
}

func testKongLog(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("testKongLog", func(_ *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(tenantsPath+tenantIdentifier+"/mep/kong_log", extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.MepController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		// Test query
		queryController.KongLog()
		queryController.Subscribe()

		// Check for error case wherein the status value will be default i.e. 0
		assert.Equal(t, 500, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		})
}