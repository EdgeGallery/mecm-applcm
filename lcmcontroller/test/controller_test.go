package test

import (
	"lcmcontroller/controllers"
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

var (
	FILE_PERMISSION os.FileMode = 0750
	DIRECTORY                   = "/usr/app"
	HOST_IP                     = "1.1.1.1"
)

func TestInstantiateSuccess(t *testing.T) {

	_ = os.Mkdir(DIRECTORY, FILE_PERMISSION)

	// Setting file path
	path, _ := os.Getwd()
	path += "/22406fba-fd5d-4f55-b3fa-89a45fee913a.csar"

	// Setting extra parameters
	extraParams := map[string]string{
		"hostIp": HOST_IP,
	}

	// Get Request
	request, _ := newfileUploadRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/e921ce54-82c8-4532-b5c6-"+
		"8516cf75f7a6/app_instances/e921ce54-82c8-4532-b5c6-8516cf75f7a4/instantiate", extraParams, "file", path)

	// Prepare Input
	input := &context.BeegoInput{Context: &context.Context{Request: request}}
	input.SetParam(":tenantId", "e921ce54-82c8-4532-b5c6-8516cf75f7a6")
	input.SetParam(":appInstanceId", "e921ce54-82c8-4532-b5c6-8516cf75f7a4")

	// Prepare beego controller
	beegoController := beego.Controller{Ctx: &context.Context{Input: input, Request: request,
		ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
		Data: make(map[interface{}]interface{})}

	// Create LCM controller with mocked DB and prepared Beego controller
	controller := &controllers.LcmController{Db: &MockDb{}, Controller: beegoController}

	// Mock the client
	patch1 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
		return &MockClient{}, nil
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

	// Test instantiate
	controller.Instantiate()

	_ = os.RemoveAll(DIRECTORY)

	// Check for success case wherein the status value will be default i.e. 0
	assert.Equal(t, 0, controller.Ctx.ResponseWriter.Status, "TestInstantiateSuccess failed")
}

func TestUploadSuccess(t *testing.T) {

	_ = os.Mkdir(DIRECTORY, FILE_PERMISSION)

	// Setting file path
	path, _ := os.Getwd()
	path += "/config"

	// Setting extra parameters
	extraParams := map[string]string{
		"hostIp": HOST_IP,
	}

	// Get Request
	request, _ := newfileUploadRequest("https://edgegallery:8094/lcmcontroller/v1/configuration", extraParams,
		"configFile", path)

	// Prepare Input
	input := &context.BeegoInput{Context: &context.Context{Request: request}}
	input.SetParam(":tenantId", "e921ce54-82c8-4532-b5c6-8516cf75f7a6")
	input.SetParam(":appInstanceId", "e921ce54-82c8-4532-b5c6-8516cf75f7a4")

	// Prepare beego controller
	beegoController := beego.Controller{Ctx: &context.Context{Input: input, Request: request,
		ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
		Data: make(map[interface{}]interface{})}

	// Create LCM controller with mocked DB and prepared Beego controller
	controller := &controllers.LcmController{Db: &MockDb{}, Controller: beegoController}

	// Mock the client
	patch1 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
		return &MockClient{}, nil
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

	// Test instantiate
	controller.UploadConfig()

	_ = os.RemoveAll(DIRECTORY)

	// Check for success case wherein the status value will be default i.e. 0
	assert.Equal(t, 0, controller.Ctx.ResponseWriter.Status, "TestUploadSuccess failed")
}
