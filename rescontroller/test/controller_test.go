package test

import (
	"encoding/json"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"rescontroller/controllers"
	"rescontroller/pkg/dbAdapter"
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
			"providerSegmentationId":"",
			"qosPolicyId": "",
			"routerExternal": true,
			"segments" :"\"[" + "{" + "providerSegmentationId"+":"+"\"1," +
				"providerPhysicalNetwork"+":" +" "+","+"providerNetworkType"+":"+ ""+"}"+"\"]",
			"shared": true,
			"vlanTransparent": true,
			"isDefault": true,
			"subnets": "\"[" + "{" +
			"name"+":"+ "subnetA",
			"enableDhcp": true,
			"dnsNameservers":"\"["+
			""+","+""+"\"]",
			"allocationPools":"\"[" + "{" +
			"start"+":"+ "192.168.xxx.5",
			"end": "192.168.xxx.25"+"}"+"\"]",
			"ipVersion":"",
			"gatewayIp": "192.168.xxx.1",
			"cidr": "10.0.0.0/24",
			"ipv6AddressMode": "",
			"ipv6RaMode":"" +"}"+"\"]"})

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
		assert.Equal(t, 200, networkController.Ctx.ResponseWriter.Status, "Delete network success")
	})
}

func setParam(ctx *context.BeegoInput) {
	ctx.SetParam(tenantId, tenantIdentifier)
	ctx.SetParam(":appInstanceId", appInstanceIdentifier)
	ctx.SetParam(":packageId", packageId)
	ctx.SetParam(":hostIp", ipAddress)
}
