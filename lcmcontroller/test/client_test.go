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
	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego"
	"io/ioutil"
	"lcmcontroller/controllers"
	"lcmcontroller/models"
	"lcmcontroller/util"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"
)

var (
	k8sPluginAddr     = "127.0.0.1"
	k8sPluginPort     = "10001"
	k8sPluginEndPoint = "127.0.0.1:10001"
)

func TestWithClient(t *testing.T) {

	go startServer()
	time.Sleep(1000 * time.Millisecond)
	doTest(t)
}

func doTest(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(util.GetAppConfig, func(k string) string {
		if k == "client_ssl_enable" {
			return "false"
		}
		if k == "clientProtocol" {
			return "grpc"
		}
		return ""
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

	// Set environment variables for lcmcontroller for k8spluging
	_ = os.Setenv("K8S_PLUGIN", k8sPluginAddr)
	_ = os.Setenv("K8S_PLUGIN_PORT", k8sPluginPort)

	// Common steps
	baseDir, _ := os.Getwd()
	path := baseDir + "/positioning_with_mepagent_new.csar"
	controllers.PackageFolderPath = baseDir + directory
	_ = os.Mkdir(baseDir+directory, filePermission)
	extraParams := map[string]string{
		"hostIp":  "1.1.1.1",
		"appName": "postioning-service",
		"packageId": "e261211d80d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98",
		"appId": "e261211d80d04cb6aed00e5cd1f2cd11",
	}

	testDb := &mockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords: make(map[string]models.TenantInfoRecord),
		appPackageRecords: make(map[string]models.AppPackageRecord),
		mecHostRecords: make(map[string]models.MecHost),
		appPackageHostRecords: make(map[string]models.AppPackageHostRecord)}

	//Upload package
	testUploadPackage(t, extraParams, path, testDb)

	testAddMecHost(t, extraParams, testDb)

	//Distribute package
	testDistributePackage(t, extraParams, testDb)
	testDistributePackageV2(t, extraParams, testDb)

	// Test instantiate
	testInstantiate(t, extraParams, testDb)

	// Test work load events
	testWorkloadEvents(t, nil, "", testDb, "Success")

	// Test create image
	testCreateImage(t, extraParams, testDb)

	// Test get image
	testGetImage(t, extraParams, testDb)

	// Test get image file
	testGetImageFile(t, extraParams, testDb)

	// Test delete image file
	testDeleteImage(t, extraParams, testDb)

	// Test query
	testQuery(t, nil, "", testDb, "{\"Output\":\"Success\"}")

	// Test delete package
	testDeletePackageOnHost(t, extraParams, testDb)
	testDeletePackageOnHostV2(t, extraParams, testDb)

	// Update path to config file
	path, _ = os.Getwd()
	path += "/config"

	// Test upload
	testUpload(t, extraParams, path, testDb)

	// Test removal
	testRemoval(t, extraParams, path, testDb)

	// Test terminate
	testTerminate(t, nil, "", testDb)

	// Common cleaning state
	// Clear the created artifacts
	_ = os.RemoveAll(baseDir + directory)

}

func startServer() {
	// Start GRPC Server
	grpcServer := &ServerGRPC{Address: k8sPluginEndPoint}
	// Start listening
	_ = grpcServer.Listen()
}
