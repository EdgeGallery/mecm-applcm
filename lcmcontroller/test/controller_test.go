package test

import (
	"lcmcontroller/controllers"
	"lcmcontroller/models"
	"lcmcontroller/pkg/dbAdapter"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/stretchr/testify/assert"
)

const (
	FILE_PERMISSION os.FileMode = 0750
	DIRECTORY                   = "/usr/app"
	HOST_IP                     = "1.1.1.1"
	TENANT_ID                   = "e921ce54-82c8-4532-b5c6-8516cf75f7a6"
	APP_INSTANCE_ID             = "e921ce54-82c8-4532-b5c6-8516cf75f7a4"
)

func TestLcm(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
		return &mockClient{}, nil
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

	// Common steps
	_ = os.Mkdir(DIRECTORY, FILE_PERMISSION)
	path, _ := os.Getwd()
	path += "/22406fba-fd5d-4f55-b3fa-89a45fee913a.csar"
	extraParams := map[string]string{
		"hostIp": HOST_IP,
	}

	testDb := &mockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords: make(map[string]models.TenantInfoRecord)}

	// Test instantiate
	testInstantiate(t, extraParams, path, testDb)

	// Test query
	testQuery(t, extraParams, path, testDb)

	// Test terminate
	testTerminate(t, extraParams, path, testDb)

	// Common cleaning state
	// Clear the created artifacts
	_ = os.RemoveAll(DIRECTORY)
}

func TestConfigUpload(t *testing.T) {

	// Common steps
	// Create directory
	_ = os.Mkdir(DIRECTORY, FILE_PERMISSION)
	// Setting file path
	path, _ := os.Getwd()
	path += "/config"
	// Setting extra parameters
	extraParams := map[string]string{
		"hostIp": HOST_IP,
	}

	// Mock the client
	patch1 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
		return &mockClient{}, nil
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

	// Test upload
	testUpload(t, extraParams, path)

	// Test removal
	testRemoval(t, extraParams, path)

	// Common cleaning state
	// Clear the created artifacts
	_ = os.RemoveAll(DIRECTORY)
}

func testQuery(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

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
		assert.Equal(t, 0, queryController.Ctx.ResponseWriter.Status, "Query failed")
		assert.Equal(t, SUCCESS_RETURN, queryController.Data["json"], "Query failed")
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
	ctx.SetParam(":tenantId", TENANT_ID)
	ctx.SetParam(":appInstanceId", APP_INSTANCE_ID)
}
