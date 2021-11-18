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



func setParam(ctx *context.BeegoInput) {
	ctx.SetParam(tenantId, tenantIdentifier)
	ctx.SetParam(":appInstanceId", appInstanceIdentifier)
	ctx.SetParam(":packageId", packageId)
	ctx.SetParam(":hostIp", ipAddress)
}
