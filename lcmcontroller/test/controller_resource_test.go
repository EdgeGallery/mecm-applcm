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
	"lcmcontroller/controllers"
	"lcmcontroller/models"
	"lcmcontroller/util"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/astaxie/beego/context"
	"github.com/stretchr/testify/assert"

	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego"
)

var (
	//output = "{\"cpuusage\":{\"total\":1599629203.638,\"used\":\"0.3125\"},\"memusage\":{\"total\":1599629203.722,\"used\":\"0.025087691598781055\"},\"diskusage\":{\"total\":1599629203.801,\"used\":\"0.0000000000021572230319438497\"}}"
	cpuOutput        = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"metric\":{},\"value\":[1599646388.843,\"0.3125\"]}]}}"
	cpuQuery         = "query=sum(kube_pod_container_resource_requests_cpu_cores)/sum(kube_node_status_allocatable_cpu_cores)"
	memOutput        = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"metric\":{},\"value\":[1599647046.214,\"0.025087691598781055\"]}]}}"
	memQuery         = "query=sum(kube_pod_container_resource_requests_memory_bytes)/sum(kube_node_status_allocatable_memory_bytes)"
	diskQuery        = "query=(sum(node_filesystem_size_bytes)-sum(node_filesystem_free_bytes))/sum(node_filesystem_size_bytes)/sum(node_filesystem_size_bytes)"
	diskOutput       = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"metric\":{},\"value\":[1599647141.594,\"0.0000000000022286734699480752\"]}]}}"
	finalOutput      = "{\"cpuusage\":{\"total\":1599646388.843,\"used\":\"0.3125\"},\"memusage\":{\"total\":1599647046.214,\"used\":\"0.025087691598781055\"},\"diskusage\":{\"total\":1599647141.594,\"used\":\"0.0000000000022286734699480752\"}}"
	capabilityOutput = "{\"Output\":\"Success\"}"
)

func TestKpi(t *testing.T) {

	// Mock the required API
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

	// Create server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == cpuQuery {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(cpuOutput))
		}
		if r.URL.RawQuery == memQuery {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(memOutput))
		}
		if r.URL.RawQuery == diskQuery {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(diskOutput))
		}
	}))
	defer ts.Close()

	// Get base HOST IP and PORT of running server
	u, _ := url.Parse(ts.URL)
	parts := strings.Split(u.Host, ":")
	localIp := parts[0]
	port := parts[1]
	_ = os.Setenv("PROMETHEUS_PORT", port)

	// Common steps
	_ = os.Mkdir(DIRECTORY, FILE_PERMISSION)
	path, _ := os.Getwd()
	path += "/22406fba-fd5d-4f55-b3fa-89a45fee913a.csar"
	extraParams := map[string]string{
		"hostIp": localIp,
	}
	testDb := &mockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords: make(map[string]models.TenantInfoRecord)}

	t.Run("TestGetKpi", func(t *testing.T) {

		// Get Request
		kpiRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/"+TENANT_ID+
			"/hosts/"+localIp+"/kpi", extraParams, "file", path, "GET")

		// Prepare Input
		kpiInput := &context.BeegoInput{Context: &context.Context{Request: kpiRequest}}
		setRessourceParam(kpiInput, localIp)

		// Prepare beego controller
		kpiBeegoController := beego.Controller{Ctx: &context.Context{Input: kpiInput,
			Request: kpiRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		kpiController := &controllers.LcmController{Db: testDb, Controller: kpiBeegoController}

		// Test KPI
		kpiController.QueryKPI()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, kpiController.Ctx.ResponseWriter.Status, "Get KPI failed")
		assert.Equal(t, finalOutput, kpiController.Data["json"], "Query failed")
	})

	// Common cleaning state
	// Clear the created artifacts
	_ = os.RemoveAll(DIRECTORY)
}

func TestMepCapabilities(t *testing.T) {

	// Mock the required API
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

	// Create server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(capabilityOutput))
	}))
	defer ts.Close()

	// Get base HOST IP and PORT of running server
	u, _ := url.Parse(ts.URL)
	parts := strings.Split(u.Host, ":")
	localIp := parts[0]
	port := parts[1]
	_ = os.Setenv("MEP_PORT", port)

	// Common steps
	_ = os.Mkdir(DIRECTORY, FILE_PERMISSION)
	path, _ := os.Getwd()
	path += "/22406fba-fd5d-4f55-b3fa-89a45fee913a.csar"
	extraParams := map[string]string{
		"hostIp": localIp,
	}
	testDb := &mockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords: make(map[string]models.TenantInfoRecord)}

	t.Run("TestGetCapability", func(t *testing.T) {

		// Get Request
		capabilityRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/"+TENANT_ID+
			"/hosts/"+localIp+"/mep_capabilities", extraParams, "file", path, "GET")

		// Prepare Input
		capabilityInput := &context.BeegoInput{Context: &context.Context{Request: capabilityRequest}}
		setRessourceParam(capabilityInput, localIp)

		// Prepare beego controller
		capabilityBeegoController := beego.Controller{Ctx: &context.Context{Input: capabilityInput,
			Request: capabilityRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		capabilityController := &controllers.LcmController{Db: testDb, Controller: capabilityBeegoController}

		// Test Capability
		capabilityController.QueryMepCapabilities()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, capabilityController.Ctx.ResponseWriter.Status, "Get Capability status failed")
		assert.Equal(t, capabilityOutput, capabilityController.Data["json"], "Get Capability data failed")
	})

	// Common cleaning state
	// Clear the created artifacts
	_ = os.RemoveAll(DIRECTORY)
}

func setRessourceParam(ctx *context.BeegoInput, localIp string) {
	ctx.SetParam(":tenantId", TENANT_ID)
	ctx.SetParam(":hostIp", localIp)
}
