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
 */

package test

import (
	"fmt"
	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"net/http/httptest"
	"os"
	"reflect"
	"rescontroller/controllers"
	"rescontroller/models"
	"rescontroller/util"
	"testing"
)


var (
	tenantIdentifier                  = "e921ce54-82c8-4532-b5c6-8516cf75f7a6"
	ipAddress                         = "1.1.1.1"
	ipAddFormatter = "%d.%d.%d.%d"
	fwdIp          = fmt.Sprintf(ipAddFormatter, rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal),
		rand.Intn(util.MaxIPVal))
	appInstanceIdentifier             = "e921ce54-82c8-4532-b5c6-8516cf75f7a4"
	packageId                         = "e261211d80d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98"
	tenantId                          = ":tenantId"
	commonOut = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"metric\":{},"
	cpuOutput = commonOut + "\"value\":[1599646388.843,\"0.3125\"]}]}}"
	cpuQuery  = "query=sum(kube_pod_container_resource_requests_cpu_cores)/sum(kube_node_status_" +
		"allocatable_cpu_cores)"
	memOutput = commonOut + "\"value\":[1599647046.214,\"0.025087691598781055\"]}]}}"
	memQuery  = "query=sum(kube_pod_container_resource_requests_memory_bytes)/sum(kube_node_status_" +
		"allocatable_memory_bytes)"
	diskQuery = "query=(sum(node_filesystem_size_bytes)-sum(node_filesystem_free_bytes))/sum(node_" +
		"filesystem_size_bytes)"
	diskOutput  = commonOut + "\"value\":[1599647141.594,\"0.0000000000022286734699480752\"]}]}}"
	finalOutput = "{\"cpuusage\":{\"total\":1599646388.843,\"used\":\"0.3125\"},\"memusage\":{\"total" +
		"\":1599647046.214,\"used\":\"0.025087691598781055\"},\"diskusage\":{\"total\":1599647141.594,\"used\":" +
		"\"0.0000000000022286734699480752\"}}"
	kpiOutputV2 = "{\"cpuusage\":{\"total\":1599646388.843,\"used\":\"0.3125\"},\"memusage\":{\"total\":1599647046.214,\"used\":\"0.025087691598781055\"},\"diskusage\":{\"total\":1599647141.594,\"used\":\"0.0000000000022286734699480752\"}}{\"data\":null,\"retCode\":0,\"message\":\"Query kpi is successful\",\"params\":null}"
	capabilityOutput = "{\"capabilityId\":\"1\",\"capabilityName\":\"2\",\"status\": \"ACTIVE\",\"version\": \"4.5.8\"," +
		"\"consumers\":[{\"applicationInstanceId\":\"5abe4782-2c70-4e47-9a4e-0ee3a1a0fd1f\"},{\"applicationInstanceId\":\"86dfc97d-325e-4feb-ac4f-280a0ba42513\"}]},{\"capabilityId\":\"2\",\"capabilityName\":\"2\",\"status\": \"ACTIVE\",\"version\": \"4.5.8\"," +
		"\"consumers\": [{\"applicationInstanceId\":\"88922760-861b-4578-aae5-77b8fcb06142\"}]}]\"}}"
	capabilityIdOutput = "{\"capabilityId\":\"16384563dca094183778a41ea7701d15\",\"\n\"\"capabilityName\":\"FaceRegService\",\"status\":\"Active\",\"version\": \"4.5.8\"," +
		"\"consumers\":[{\"applicationInstanceId\":\"5abe4782-2c70-4e47-9a4e-0ee3a1a0fd1f\"},{\"applicationInstanceId\":\"f05a5591-d8f2-4f89-8c0b-8cea6d45712e\"},{\"applicationInstanceId\":\"86dfc97d-325e-4feb-ac4f-280a0ba42513\"}}"
	capabilityIdOutputV2 = "{\"capabilityId\":\"16384563dca094183778a41ea7701d15\",\"\n\"\"capabilityName\":\"FaceRegService\",\"status\":\"Active\",\"version\": \"4.5.8\",\"consumers\":[{\"applicationInstanceId\":\"5abe4782-2c70-4e47-9a4e-0ee3a1a0fd1f\"},{\"applicationInstanceId\":\"f05a5591-d8f2-4f89-8c0b-8cea6d45712e\"},{\"applicationInstanceId\":\"86dfc97d-325e-4feb-ac4f-280a0ba42513\"}}{\"capabilityId\":\"16384563dca094183778a41ea7701d15\",\"\n\"\"capabilityName\":\"FaceRegService\",\"status\":\"Active\",\"version\": \"4.5.8\",\"consumers\":[{\"applicationInstanceId\":\"5abe4782-2c70-4e47-9a4e-0ee3a1a0fd1f\"},{\"applicationInstanceId\":\"f05a5591-d8f2-4f89-8c0b-8cea6d45712e\"},{\"applicationInstanceId\":\"86dfc97d-325e-4feb-ac4f-280a0ba42513\"}}{\"data\":null,\"retCode\":0,\"message\":\"Query mep capabilities is successful\",\"params\":null}"
	queryUrl             = "https://edgegallery:8094/lcmcontroller/v1/tenants/"
	serveJson            = "ServeJSON"
	csar                 = "/positioning_with_mepagent_new.csar"
	hostIp               = "hostIp"
	hosts                = "/hosts/"
	prometheusPort       = "PROMETHEUS_PORT"
	testGetKpi           = "TestGetKpi"
	getFlavorFailed         = "Get flavor failed"
	getCapability        = "Get Capability "
	statusFailed         = "status failed"
	getCapabilityDataFailed = "Get Capability data failed"
	hwcapabilities          = "[{\"hwType\": \"GPU1\", \"hwVendor\": \"testvendor1\", \"hwModel\": \"testmodel1\"}]"
)


func TestQueryFlavorSuccess(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(util.ClearByteArray, func(_ []byte) {
		// do nothing
	})
	defer patch1.Reset()

	var c *beego.Controller
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), serveJson, func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch2.Reset()


	//// Common steps
	_, extraParams, testDb := getCommonParameters("127.0.0.1")

	t.Run("TestGetFlavor", func(t *testing.T) {

		// Get Request
		flavorRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/"+tenantIdentifier+
			hosts+ipAddress+"/flavor", extraParams, "file", "", "GET", []byte(""))

		// Prepare Input
		flavorInput := &context.BeegoInput{Context: &context.Context{Request: flavorRequest}}
		setRessourceParam(flavorInput, ipAddress)

		// Prepare beego controller
		flavorBeegoController := beego.Controller{Ctx: &context.Context{Input: flavorInput,
			Request: flavorRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		flavorController := &controllers.FlavorController{controllers.BaseController{Db: testDb,
			Controller: flavorBeegoController}}

		//testAddMecHost(t, extraParams, testDb)
		// Test KPI
		flavorController.QueryFlavor()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, flavorController.Ctx.ResponseWriter.Status, getFlavorFailed)

		//response := kpiController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

	})
}

func TestQuerySecurityGroupSuccess(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(util.ClearByteArray, func(_ []byte) {
		// do nothing
	})
	defer patch1.Reset()

	var c *beego.Controller
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), serveJson, func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch2.Reset()


	//// Common steps
	_, extraParams, testDb := getCommonParameters("127.0.0.1")

	t.Run("TestGetSecurityGroup", func(t *testing.T) {

		// Get Request
		securityGroupRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/"+tenantIdentifier+
			hosts+ipAddress+"/securityGroup", extraParams, "file", "", "GET", []byte(""))

		// Prepare Input
		securityGroupInput := &context.BeegoInput{Context: &context.Context{Request: securityGroupRequest}}
		setRessourceParam(securityGroupInput, ipAddress)

		// Prepare beego controller
		sgBeegoController := beego.Controller{Ctx: &context.Context{Input: securityGroupInput,
			Request: securityGroupRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		securityGroupController := &controllers.SecurityGroupController{controllers.BaseController{Db: testDb,
			Controller: sgBeegoController}}

		// Test KPI
		securityGroupController.QuerySecurityGroup()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, securityGroupController.Ctx.ResponseWriter.Status, "Get security group failed")
	})
}

func TestQuerySecurityGroupRulesSuccess(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(util.ClearByteArray, func(_ []byte) {
		// do nothing
	})
	defer patch1.Reset()

	var c *beego.Controller
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), serveJson, func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch2.Reset()


	//// Common steps
	_, extraParams, testDb := getCommonParameters("127.0.0.1")

	t.Run("TestGetSecurityGroupRules", func(t *testing.T) {

		// Get Request
		securityGroupRuleRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/"+tenantIdentifier+
			hosts+ipAddress+"/securityGroup", extraParams, "file", "", "GET", []byte(""))

		// Prepare Input
		securityGroupRuleInput := &context.BeegoInput{Context: &context.Context{Request: securityGroupRuleRequest}}
		setRessourceParam(securityGroupRuleInput, ipAddress)

		// Prepare beego controller
		sgrBeegoController := beego.Controller{Ctx: &context.Context{Input: securityGroupRuleInput,
			Request: securityGroupRuleRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		securityGroupController := &controllers.SecurityGroupController{controllers.BaseController{Db: testDb,
			Controller: sgrBeegoController}}

		// Test KPI
		securityGroupController.QuerySecurityGroupRules()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, securityGroupController.Ctx.ResponseWriter.Status, "Get security group rules failed")
	})
}

func TestQueryServerSuccess(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(util.ClearByteArray, func(_ []byte) {
		// do nothing
	})
	defer patch1.Reset()

	var c *beego.Controller
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), serveJson, func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch2.Reset()


	//// Common steps
	_, extraParams, testDb := getCommonParameters("127.0.0.1")

	t.Run("TestGetServer", func(t *testing.T) {

		// Get Request
		serverRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/"+tenantIdentifier+
			hosts+ipAddress+"/servers", extraParams, "file", "", "GET", []byte(""))

		// Prepare Input
		serverInput := &context.BeegoInput{Context: &context.Context{Request: serverRequest}}
		setRessourceParam(serverInput, ipAddress)

		// Prepare beego controller
		serverBeegoController := beego.Controller{Ctx: &context.Context{Input: serverInput,
			Request: serverRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		serverController := &controllers.VmController{controllers.BaseController{Db: testDb,
			Controller: serverBeegoController}}

		// Test KPI
		serverController.QueryServer()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, serverController.Ctx.ResponseWriter.Status, "Get server failed")
	})
}

func TestQueryImageSuccess(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(util.ClearByteArray, func(_ []byte) {
		// do nothing
	})
	defer patch1.Reset()

	var c *beego.Controller
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), serveJson, func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch2.Reset()


	//// Common steps
	_, extraParams, testDb := getCommonParameters("127.0.0.1")

	t.Run("TestGetImage", func(t *testing.T) {

		// Get Request
		imageRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/"+tenantIdentifier+
			hosts+ipAddress+"/images", extraParams, "file", "", "GET", []byte(""))

		// Prepare Input
		imageInput := &context.BeegoInput{Context: &context.Context{Request: imageRequest}}
		setRessourceParam(imageInput, ipAddress)

		// Prepare beego controller
		imageBeegoController := beego.Controller{Ctx: &context.Context{Input: imageInput,
			Request: imageRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		imageController := &controllers.VmImageController{controllers.BaseController{Db: testDb,
			Controller: imageBeegoController}}

		// Test images
		imageController.QueryImages()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, imageController.Ctx.ResponseWriter.Status, "Get image failed")
	})
}

func getCommonParameters(localIp string) (string, map[string]string, *MockDb) {
	path, _ := os.Getwd()
	path += csar
	extraParams := map[string]string{
		hostIp: localIp,
	}
	testDb := &MockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		mecHostRecords: make(map[string]models.MecHost),
		}
	hostInfoRecord := &models.MecHost{
		MechostIp: ipAddress,
		MechostName: "edgegallery",
		ZipCode: "560048",
		City: "xian",
		Address: "xian",
		Affinity: "shenzhen",
		UserName: "root",
		Coordinates:"1,2",
	}
	testDb.mecHostRecords["1.1.1.1"] = *hostInfoRecord
	return path, extraParams, testDb
}

func setRessourceParam(ctx *context.BeegoInput, localIp string) {
	ctx.SetParam(":tenantId", tenantIdentifier)
	ctx.SetParam(":hostIp", localIp)
}