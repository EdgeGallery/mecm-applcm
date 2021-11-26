package test

import (
	"encoding/json"
	"errors"
	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/stretchr/testify/assert"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"net/http/httptest"
	"rescontroller/controllers"
	"rescontroller/pkg/dbAdapter"
	"rescontroller/util"
	"testing"
)

func testCreateFlavor(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestCreateFlavor", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]interface{}{
			"name": "test_flavor",
			"vcpus": 2,
			"ram": 1024,
			"disk": 10,
			"swap": 10,
		})

		// Get Request
		flavorRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/flavor", extraParams,
			"package", "", "POST", requestBody)

		// Prepare Input
		flavorInput := &context.BeegoInput{Context: &context.Context{Request: flavorRequest}, RequestBody: requestBody}
		setParam(flavorInput)

		// Prepare beego controller
		flavorBeegoController := beego.Controller{Ctx: &context.Context{Input: flavorInput,
			Request: flavorRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create flavor controller with mocked DB and prepared Beego controller
		flavorController := &controllers.FlavorController{controllers.BaseController{Db: testDb,
			Controller: flavorBeegoController}}

		// Test Add mec host
		flavorController.CreateFlavor()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, flavorController.Ctx.ResponseWriter.Status, "Create flavor success")
	})
}

func testDeleteFlavor(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeleteFlavor", func(t *testing.T) {

		// Get Request
		flavorRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/flavor", extraParams,
			"package", "", "DELETE", []byte(""))

		// Prepare Input
		flavorInput := &context.BeegoInput{Context: &context.Context{Request: flavorRequest}}
		setParam(flavorInput)

		// Prepare beego controller
		flavorBeegoController := beego.Controller{Ctx: &context.Context{Input: flavorInput,
			Request: flavorRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create flavor controller with mocked DB and prepared Beego controller
		flavorController := &controllers.FlavorController{controllers.BaseController{Db: testDb,
			Controller: flavorBeegoController}}

		// Test Add mec host
		flavorController.DeleteFlavor()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, flavorController.Ctx.ResponseWriter.Status, "Create flavor success")
	})
}

func testCreateSecurityGroup(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestCreateSecurityGroup", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]interface{}{
			"name": "new-webservers",
		})

		// Get Request
		sgRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/securityGroup", extraParams,
			"package", "", "POST", requestBody)

		// Prepare Input
		sgInput := &context.BeegoInput{Context: &context.Context{Request: sgRequest}, RequestBody: requestBody}
		setParam(sgInput)

		// Prepare beego controller
		sgBeegoController := beego.Controller{Ctx: &context.Context{Input: sgInput,
			Request: sgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create security group controller with mocked DB and prepared Beego controller
		sgController := &controllers.SecurityGroupController{controllers.BaseController{Db: testDb,
			Controller: sgBeegoController}}

		// Test create security group
		sgController.CreateSecurityGroup()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, sgController.Ctx.ResponseWriter.Status, "Create security group success")
	})
}

func testDeleteSecurityGroup(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeleteSecurityGroup", func(t *testing.T) {

		// Get Request
		sgRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/securityGroup", extraParams,
			"package", "", "DELETE",  []byte(""))

		// Prepare Input
		sgInput := &context.BeegoInput{Context: &context.Context{Request: sgRequest}}
		setParam(sgInput)

		// Prepare beego controller
		sgBeegoController := beego.Controller{Ctx: &context.Context{Input: sgInput,
			Request: sgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create security group controller with mocked DB and prepared Beego controller
		sgController := &controllers.SecurityGroupController{controllers.BaseController{Db: testDb,
			Controller: sgBeegoController}}

		// Test create security group
		sgController.DeleteSecurityGroup()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, sgController.Ctx.ResponseWriter.Status, "Create security group success")
	})
}

func testCreateSecurityGroupRule(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestCreateSecurityGroupRule", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]interface{}{
			"securityGroupId": "a7734e61-b545-452d-a3cd-0189cbd9747a",
			"direction": "ingress",
			"protocol": "tcp",
			"ethertype": "IPv4",
			"port_range_min": 80,
			"port_range_max": 90,
			"remoteIpPrefix": "",
			"remote_group_id": "85cc3048-abc3-43cc-89b3-377341426ac5",
		})

		// Get Request
		sgRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/securityGroups/:securityGroupId/securityGroupRules", extraParams,
			"package", "", "POST", requestBody)

		// Prepare Input
		sgInput := &context.BeegoInput{Context: &context.Context{Request: sgRequest}, RequestBody: requestBody}
		setParam(sgInput)

		// Prepare beego controller
		sgBeegoController := beego.Controller{Ctx: &context.Context{Input: sgInput,
			Request: sgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create security group controller with mocked DB and prepared Beego controller
		sgController := &controllers.SecurityGroupController{controllers.BaseController{Db: testDb,
			Controller: sgBeegoController}}

		// Test create security group
		sgController.CreateSecurityGroupRules()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, sgController.Ctx.ResponseWriter.Status, "Create security group success")
	})
}

func testDeleteSecurityGroupRule(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeleteSecurityGroup", func(t *testing.T) {

		// Get Request
		sgRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/securityGroup/:securityGroupId/securityGroupRules/:securityGroupRuleId", extraParams,
			"package", "", "DELETE",  []byte(""))

		// Prepare Input
		sgInput := &context.BeegoInput{Context: &context.Context{Request: sgRequest}}
		setParam(sgInput)

		// Prepare beego controller
		sgBeegoController := beego.Controller{Ctx: &context.Context{Input: sgInput,
			Request: sgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create security group controller with mocked DB and prepared Beego controller
		sgController := &controllers.SecurityGroupController{controllers.BaseController{Db: testDb,
			Controller: sgBeegoController}}

		// Test create security group
		sgController.DeleteSecurityGroupRules()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, sgController.Ctx.ResponseWriter.Status, "Create security group success")
	})
}

func testCreateImage(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestCreateImage", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]interface{}{
			"name": "test",
			"containerFormat": "test",
			"diskFormat": "ssd",
			"minRam": 1,
			"minDisk": 10,
		})

		// Get Request
		createImageRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/images/:imageId", extraParams,
			"package", "", "POST", requestBody)

		// Prepare Input
		createImageInput := &context.BeegoInput{Context: &context.Context{Request: createImageRequest}, RequestBody: requestBody}
		setParam(createImageInput)

		// Prepare beego controller
		createImageBeegoController := beego.Controller{Ctx: &context.Context{Input: createImageInput,
			Request: createImageRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create image controller with mocked DB and prepared Beego controller
		createImageController := &controllers.VmImageController{controllers.BaseController{Db: testDb,
			Controller: createImageBeegoController}}

		// Test create security group
		createImageController.CreateImage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, createImageController.Ctx.ResponseWriter.Status, "Create image success")
	})
}

func testImportImage(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestCreateImage", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]interface{}{
				"imageId": "1234",
				"resourceUri": "http://sample",
		})

		// Get Request
		createImageRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/images/:imageId", extraParams,
			"package", "", "POST", requestBody)

		// Prepare Input
		createImageInput := &context.BeegoInput{Context: &context.Context{Request: createImageRequest}, RequestBody: requestBody}
		setParam(createImageInput)

		// Prepare beego controller
		createImageBeegoController := beego.Controller{Ctx: &context.Context{Input: createImageInput,
			Request: createImageRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create image controller with mocked DB and prepared Beego controller
		createImageController := &controllers.VmImageController{controllers.BaseController{Db: testDb,
			Controller: createImageBeegoController}}

		// Test create security group
		createImageController.ImportImage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, createImageController.Ctx.ResponseWriter.Status, "Create image success")
	})
}

func testDeleteImage(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestDeleteImage", func(t *testing.T) {

		// Get Request
		createImageRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/securityGroups/:securityGroupId/securityGroupRules", extraParams,
			"package", "", "DELETE",   []byte(""))

		// Prepare Input
		createImageInput := &context.BeegoInput{Context: &context.Context{Request: createImageRequest}}
		setParam(createImageInput)

		// Prepare beego controller
		createImageBeegoController := beego.Controller{Ctx: &context.Context{Input: createImageInput,
			Request: createImageRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create image controller with mocked DB and prepared Beego controller
		createImageController := &controllers.VmImageController{controllers.BaseController{Db: testDb,
			Controller: createImageBeegoController}}

		// Test create security group
		createImageController.DeleteImage()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, createImageController.Ctx.ResponseWriter.Status, "Create image success")
	})
}

func testCreateServer(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestCreateServer", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]interface{}{
			"name": "vmTest",
			"flavor": "0e12087a-7c87-476a-8f84-7398e991cecc",
			"image" : "cec3aab9-5991-4893-befe-4775ddf79de6",
			"imageRef" : "70a599e0-31e7-49b7-b260-868f441e862b",
			"availabilityZone": "us-west",
			"user_data" : "IyEvYmluL2Jhc2gKL2Jpbi9zdQplY2hvICJJIGFtIGluIHlvdSEiCg==",
			"configDrive": true,
		})

		// Get Request
		createServerRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/servers", extraParams,
			"package", "", "POST", requestBody)

		// Prepare Input
		createServerInput := &context.BeegoInput{Context: &context.Context{Request: createServerRequest}, RequestBody: requestBody}
		setParam(createServerInput)

		// Prepare beego controller
		createServerBeegoController := beego.Controller{Ctx: &context.Context{Input: createServerInput,
			Request: createServerRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create image controller with mocked DB and prepared Beego controller
		createServerController := &controllers.VmController{controllers.BaseController{Db: testDb,
			Controller: createServerBeegoController}}

		// Test create server
		createServerController.CreateServer()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, createServerController.Ctx.ResponseWriter.Status, "Create server success")
	})
}

func testOperateServer(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestOperateServer", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]interface{}{
			"action" : "any",
			"reboot" : "true",
		})

		// Get Request
		createServerRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/servers", extraParams,
			"package", "", "POST", requestBody)

		// Prepare Input
		createServerInput := &context.BeegoInput{Context: &context.Context{Request: createServerRequest}, RequestBody: requestBody}
		setParam(createServerInput)

		// Prepare beego controller
		createServerBeegoController := beego.Controller{Ctx: &context.Context{Input: createServerInput,
			Request: createServerRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create image controller with mocked DB and prepared Beego controller
		createServerController := &controllers.VmController{controllers.BaseController{Db: testDb,
			Controller: createServerBeegoController}}

		// Test create server
		createServerController.OperateServer()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, createServerController.Ctx.ResponseWriter.Status, "Operate server success")
	})
}

func testDeleteServer(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestDeleteServer", func(t *testing.T) {

		// Get Request
		createServerRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/servers", extraParams,
			"package", "", "DELETE", []byte(""))

		// Prepare Input
		createServerInput := &context.BeegoInput{Context: &context.Context{Request: createServerRequest}}
		setParam(createServerInput)

		// Prepare beego controller
		createServerBeegoController := beego.Controller{Ctx: &context.Context{Input: createServerInput,
			Request: createServerRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create image controller with mocked DB and prepared Beego controller
		createServerController := &controllers.VmController{controllers.BaseController{Db: testDb,
			Controller: createServerBeegoController}}

		// Test create server
		createServerController.DeleteServer()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 200, createServerController.Ctx.ResponseWriter.Status, "Operate server success")

		// Test Ratelimiter
		r := &util.RateLimiter{}
		rate, _ := limiter.NewRateFromFormatted("200-S")
		r.GeneralLimiter = limiter.New(memory.NewStore(), rate)
		util.RateLimit(r, createServerController.Ctx)

		// Test handle logging for error
		createServerController.HandleLoggingForError(ipAddress, 400, "failed to delete directory")

		// Test handle logging for error
		createServerController.HandleLoggingForTokenFailure(ipAddress, util.Forbidden)

		// Test handle logging for error
		createServerController.HandleLoggingForTokenFailure(ipAddress, "forbidden1")

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController1 := &controllers.ErrorController{Controller:createServerBeegoController}

		instantiateController1.Error404()
	})
}

func testDeleteServer1(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestDeleteServer", func(t *testing.T) {

		// Get Request
		createServerRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/servers", extraParams,
			"package", "", "DELETE", []byte(""))
		createServerRequest.Header.Set("access_token", "")
		createServerRequest.Header.Set("name", "user")
		createServerRequest.Header.Set("key", "fe0Hmv%sbq")
		// Prepare Input
		createServerInput := &context.BeegoInput{Context: &context.Context{Request: createServerRequest}}
		setParam(createServerInput)

		// Prepare beego controller
		createServerBeegoController := beego.Controller{Ctx: &context.Context{Input: createServerInput,
			Request: createServerRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create image controller with mocked DB and prepared Beego controller
		createServerController := &controllers.VmController{controllers.BaseController{Db: testDb,
			Controller: createServerBeegoController}}

		// Test create server
		createServerController.DeleteServer()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, createServerController.Ctx.ResponseWriter.Status, "Operate server success")

		createServerInput.SetParam(tenantId, tenantIdentifier)
		createServerInput.SetParam(":hostIp", "1234")

		// Test create server
		createServerController.DeleteServer()
		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, createServerController.Ctx.ResponseWriter.Status, "Operate server success")
		createServerRequest.Header.Set("key", "a")
		createServerInput.SetParam(":hostIp", ipAddress)

		// Test create server
		createServerController.DeleteServer()
		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, createServerController.Ctx.ResponseWriter.Status, "Operate server success")

		createServerRequest.Header.Set("name", "abcdefghijklmnopq")

		// Test create server
		createServerController.DeleteServer()
		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, createServerController.Ctx.ResponseWriter.Status, "Operate server success")

		createServerInput.SetParam(tenantId, "1234")

		// Test create server
		createServerController.DeleteServer()
		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, createServerController.Ctx.ResponseWriter.Status, "Operate server success")
	})
}

func testDeleteServer2(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestDeleteServer", func(t *testing.T) {

		// Get Request
		createServerRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/servers", extraParams,
			"package", "", "DELETE", []byte(""))

		// Prepare Input
		createServerInput := &context.BeegoInput{Context: &context.Context{Request: createServerRequest}}
		setParam(createServerInput)

		// Prepare beego controller
		createServerBeegoController := beego.Controller{Ctx: &context.Context{Input: createServerInput,
			Request: createServerRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create image controller with mocked DB and prepared Beego controller
		createServerController := &controllers.VmController{controllers.BaseController{Db: testDb,
			Controller: createServerBeegoController}}
		createServerInput.SetParam(":hostIp", "1234")

		// Test delete server
		createServerController.DeleteServer()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, createServerController.Ctx.ResponseWriter.Status, "Delete server success")
		//case-1
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return errors.New("failed to validate src address")
		})
		defer patch1.Reset()
		// Test create server
		createServerController.DeleteServer()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, createServerController.Ctx.ResponseWriter.Status, "Delete server success")
	})
}

func testCreateNetwork(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestCreateNetwork", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]interface{}{
			"name": "sample_network",
			"adminStateUp": true,
			"dnsDomain": "my-domain.org.",
			"mtu": 1400,
			"portSecurityEnabled": true,
			"providerNetworkType":"",
			"providerPhysicalNetwork":"",
			"providerSegmentationId":1,
			"qosPolicyId": "",
			"routerExternal": true,
			"shared": true,
			"vlanTransparent": true,
			"isDefault": true,
			})

		// Get Request
		networkRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/networks", extraParams,
			"package", "", "POST", requestBody)

		// Prepare Input
		networkInput := &context.BeegoInput{Context: &context.Context{Request: networkRequest}, RequestBody: requestBody}
		setParam(networkInput)

		// Prepare beego controller
		networkBeegoController := beego.Controller{Ctx: &context.Context{Input: networkInput,
			Request: networkRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create network controller with mocked DB and prepared Beego controller
		networkController := &controllers.NetworkController{controllers.BaseController{Db: testDb,
			Controller: networkBeegoController}}

		// Test Add mec host
		networkController.CreateNetwork()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 0, networkController.Ctx.ResponseWriter.Status, "Create network success")
	})
}

func testDeleteNetwork(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeleteNetwork", func(t *testing.T) {

		// Get Request
		networkRequest, _ := getHttpRequest("https://edgegallery:8094/rescontroller/v1/tenants/:tenantId/hosts/:hostIp/networks", extraParams,
			"package", "", "DELETE", []byte(""))

		// Prepare Input
		networkInput := &context.BeegoInput{Context: &context.Context{Request: networkRequest}}
		setParam(networkInput)

		// Prepare beego controller
		networkBeegoController := beego.Controller{Ctx: &context.Context{Input: networkInput,
			Request: networkRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create flavor controller with mocked DB and prepared Beego controller
		networkController := &controllers.NetworkController{controllers.BaseController{Db: testDb,
			Controller: networkBeegoController}}

		// Test Add mec host
		networkController.DeleteNetwork()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, networkController.Ctx.ResponseWriter.Status, "Delete network success")
	})
}

func setParam(ctx *context.BeegoInput) {
	ctx.SetParam(tenantId, tenantIdentifier)
	ctx.SetParam(":appInstanceId", appInstanceIdentifier)
	ctx.SetParam(":packageId", packageId)
	ctx.SetParam(":hostIp", ipAddress)
	ctx.SetParam(":serverId", tenantIdentifier)
	ctx.SetParam(":imageId", tenantIdentifier)
	ctx.SetParam(":flavorId", tenantIdentifier)
	ctx.SetParam(":securityGroupRuleId", tenantIdentifier)
	ctx.SetParam(util.SecurityGroupId, tenantIdentifier)
}
