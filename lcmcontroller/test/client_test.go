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

	patch2 := gomonkey.ApplyFunc(util.ClearByteArray, func(_ []byte) {
		// do nothing
	})
	defer patch2.Reset()

	var c *beego.Controller
	patch3 := gomonkey.ApplyMethod(reflect.TypeOf(c), "ServeJSON", func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch3.Reset()

	patch4 := gomonkey.ApplyFunc(util.DoRequest, func(_ *http.Request) (*http.Response, error) {
		// do nothing
		return &http.Response{
			Body:       ioutil.NopCloser(bytes.NewBufferString("lcmcontroller")),
			StatusCode: 200,
		}, nil
	})
	defer patch4.Reset()

	// Set environment variables for lcmcontroller for k8spluging
	_ = os.Setenv("K8S_PLUGIN", k8sPluginAddr)
	_ = os.Setenv("K8S_PLUGIN_PORT", k8sPluginPort)

	// Common steps
	baseDir, _ := os.Getwd()
	path := baseDir + "/positioning_with_mepagent_new.csar"
	controllers.PackageFolderPath = baseDir + directory
	_ = os.Mkdir(baseDir + directory, filePermission)
	extraParams := map[string]string{
		"hostIp": hostIpAddress,
	}

	testDb := &mockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords: make(map[string]models.TenantInfoRecord)}

	// Test instantiate
	testInstantiate(t, extraParams, path, testDb)

	// Test query
	testQuery(t, nil, "", testDb, "{\"Output\":\"Success\"}")

	// Test terminate
	testTerminate(t, nil, "", testDb)

	// Update path to config file
	path, _ = os.Getwd()
	path += "/config"

	// Test upload
	testUpload(t, extraParams, path)

	// Test removal
	testRemoval(t, extraParams, path)

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
