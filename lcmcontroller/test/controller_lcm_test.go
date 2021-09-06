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
	"encoding/json"
	"errors"
	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/stretchr/testify/assert"
	"lcmcontroller/controllers"
	"lcmcontroller/models"
	"lcmcontroller/pkg/dbAdapter"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

func TestControllerErr(t *testing.T) {

	// Common steps
	// Setting file path
	path, _ := os.Getwd()
	path += "/config"
	// Setting extra parameters
	extraParams := map[string]string{
		hostIpKey:  ipAddress,
		appNameKey: appName,
	}
	testDb := &MockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		tenantRecords:         make(map[string]models.TenantInfoRecord),
		appPackageRecords:     make(map[string]models.AppPackageRecord),
		mecHostRecords:        make(map[string]models.MecHost),
		appPackageHostRecords: make(map[string]models.AppPackageHostRecord)}

	var c *beego.Controller
	patch1 := gomonkey.ApplyMethod(reflect.TypeOf(c), "ServeJSON", func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch1.Reset()

	testChangeKey(t, extraParams, path, testDb)
	testGetInputParametersForChangeKey(t, extraParams, path, testDb)
	testLoginPage(t, extraParams, path, testDb)
	testGetClientIpNew(t, extraParams, path, testDb)
	testDeletePkg(t, extraParams, path, testDb)

	testTerminateApplication(t, extraParams, testDb)

	testAddMecHostErr(t, extraParams, testDb)

	testDeletePackageErr(t, extraParams, testDb)
	testSyncUpdatedMecHostRec2(t, extraParams, path, testDb)
	testBatchTerminate2(t, extraParams, testDb)

	testUploadConfigV2(t, extraParams, path, testDb)
	testUploadConfig2(t, extraParams, path, testDb)
	testUploadConfig3(t, extraParams, path, testDb)

	testUploadPkgV2(t, extraParams, path, testDb)
	testUploadPkgV2Err(t, extraParams, path, testDb)
	testGetInputParametersForUploadCfg(t, extraParams, path, testDb)

	testGetPackageDetailsFromPackage(t, extraParams, path, testDb)
	testDistributionStatus1(t, extraParams, testDb)
	testSynchronizeAppPackageUpdatedRecord1(t, extraParams, path, testDb)

	testAddMecHosts(t, extraParams, testDb)
}

func testChangeKey(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestChangeKey", func(_ *testing.T) {
		// POST Request
		keyRequest, _ := getHttpRequest(tenantsPath+tenantIdentifier+directory+packageId+hosts+ipAddress, extraParams,
			"file", path, clientIp, []byte(""))

		// Prepare Input
		keyChangeInput := &context.BeegoInput{Context: &context.Context{Request: keyRequest}}
		setParam(keyChangeInput)

		// Prepare beego controller
		keyBeegoController := beego.Controller{Ctx: &context.Context{Input: keyChangeInput,
			Request: keyRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		keyController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: keyBeegoController}}

		//case-1
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return err
		})
		defer patch1.Reset()
		keyController.ChangeKey()

		//case-2
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetInputParametersForChangeKey",
			func(_ *controllers.LcmController, clientIp string) (_ string, _ string, _ string, error error) {
				return "testUser", "", "", err
			})
		defer patch3.Reset()
		keyController.ChangeKey()

		//case-3
		patch4 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetInputParametersForChangeKey",
			func(_ *controllers.LcmController, clientIp string) (_ string, _ string, _ string, error error) {
				return "testUser", "", "", nil
			})
		defer patch5.Reset()
		keyController.ChangeKey()

		//case-4
		patch6 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch6.Reset()
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetInputParametersForChangeKey",
			func(_ *controllers.LcmController, clientIp string) (_ string, _ string, _ string, error error) {
				return "testUser", "testKey", "", nil
			})
		defer patch7.Reset()
		keyController.ChangeKey()
	})
}

func testGetInputParametersForChangeKey(t *testing.T, extraParams map[string]string,
	path string, testDb dbAdapter.Database) {

	t.Run("TestGetInputParametersForChangeKey", func(_ *testing.T) {
		// POST Request
		keyRequest, _ := getHttpRequest(tenantsPath+tenantIdentifier+directory+packageId+hosts+ipAddress, extraParams,
			"file", path, clientIp, []byte(""))

		// Prepare Input
		keyChangeInput := &context.BeegoInput{Context: &context.Context{Request: keyRequest}}
		setParam(keyChangeInput)

		// Prepare beego controller
		keyBeegoController := beego.Controller{Ctx: &context.Context{Input: keyChangeInput,
			Request: keyRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		keyController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: keyBeegoController}}

		//case-1
		_, _, _, result1 := keyController.GetInputParametersForChangeKey(clientIp)
		assert.Empty(t, result1, "Getting key Parameters For upload")

		//case-2
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetUserName",
			func(_ *controllers.LcmController, clientIp string) (_ string, error error) {
				return "testUser", err
			})
		defer patch1.Reset()
		_, _, _, result := keyController.GetInputParametersForChangeKey(clientIp)
		assert.NotEmpty(t, result, "Error getting username Parameter For upload")

		//test case:1 for GetClientIpAndValidateAccessToken
		_, _, _, clientResult := keyController.GetClientIpAndValidateAccessToken("msg",
			[]string{"ROLE_MECM_TENANT", "ROLE_MECM_ADMIN"}, "123")
		assert.NotEmpty(t, clientResult, "Error getting client ip and validating access token")

		//case-3
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetUserName",
			func(_ *controllers.LcmController, clientIp string) (_ string, error error) {
				return "testUser", nil
			})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetKey",
			func(_ *controllers.LcmController, clientIp string) (_ string, error error) {
				return "testKey", err
			})
		defer patch3.Reset()
		_, _, _, result2 := keyController.GetInputParametersForChangeKey(clientIp)
		assert.NotEmpty(t, result2, "Error getting key Parameter For upload")

		//test case:2 for GetClientIpAndValidateAccessToken
		_, _, _, clientResult2 := keyController.GetClientIpAndValidateAccessToken("msg",
			[]string{"ROLE_MECM_TENANT", "ROLE_MECM_ADMIN"}, "123")
		assert.NotEmpty(t, clientResult2, "Error getting client ip and validating access token")

		//case-4
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetUserName",
			func(_ *controllers.LcmController, clientIp string) (_ string, error error) {
				return "testUser", nil
			})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetKey",
			func(_ *controllers.LcmController, clientIp string) (_ string, error error) {
				return "testKey", nil
			})
		defer patch5.Reset()
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetNewKey",
			func(_ *controllers.LcmController, clientIp string) (_ string, error error) {
				return "newTestKey", err
			})
		defer patch6.Reset()
		_, _, _, result3 := keyController.GetInputParametersForChangeKey(clientIp)
		assert.NotEmpty(t, result3, "Error getting new key Parameter For upload")

		//test case:3 for GetClientIpAndValidateAccessToken
		baseController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: keyBeegoController}}
		accessToken := ""
		keyBeegoController.Ctx.Request.Header.Set(util.AccessToken, accessToken)

		_, _, _, clientResult3 := baseController.GetClientIpAndValidateAccessToken("msg",
			[]string{"ROLE_MECM_TENANT", "ROLE_MECM_ADMIN"}, "123")
		assert.NotEmpty(t, clientResult3, "Error getting client ip and validating access token")
	})
}

func testLoginPage(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestLoginPage", func(_ *testing.T) {

		keyRequest, _ := getHttpRequest(tenantsPath+tenantIdentifier+directory+packageId+hosts+ipAddress, extraParams,
			"file", path, clientIp, []byte(""))

		// Prepare Input
		keyChangeInput := &context.BeegoInput{Context: &context.Context{Request: keyRequest}}
		setParam(keyChangeInput)

		// Prepare beego controller
		keyBeegoController := beego.Controller{Ctx: &context.Context{Input: keyChangeInput,
			Request: keyRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		keyController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: keyBeegoController}}

		//case-1
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return err
		})
		defer patch1.Reset()
		keyController.LoginPage()

		//test case:4 for GetClientIpAndValidateAccessToken
		_, _, _, result := keyController.GetClientIpAndValidateAccessToken("msg",
			[]string{"ROLE_MECM_TENANT", "ROLE_MECM_ADMIN"}, "123")
		assert.NotEmpty(t, result, "Error getting client ip and validating access token")

		//test case:1 for GetClientIpAndValidateAccessToken
		_, _, _, _, result5 := keyController.GetClientIpAndIsPermitted("msg")
		assert.NotEmpty(t, result5, "Error getting client ip and permission")

		//case-2
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetInputParametersForChangeKey",
			func(_ *controllers.LcmController, clientIp string) (_ string, _ string, _ string, error error) {
				return "testUser", "", "", err
			})
		defer patch3.Reset()
		keyController.LoginPage()

		//case-3
		patch4 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetInputParametersForChangeKey",
			func(_ *controllers.LcmController, clientIp string) (_ string, _ string, _ string, error error) {
				return "testUser", "", "", nil
			})
		defer patch5.Reset()
		keyController.LoginPage()

		//case-4
		patch6 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch6.Reset()
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetInputParametersForChangeKey",
			func(_ *controllers.LcmController, clientIp string) (_ string, _ string, _ string, error error) {
				return "testUser", "testKey", "", nil
			})
		defer patch7.Reset()
		keyController.LoginPage()
	})
}

func testGetClientIpNew(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestGetClientIpNew", func(_ *testing.T) {

		keyRequest, _ := getHttpRequest(tenantsPath+tenantIdentifier+directory+packageId+hosts+ipAddress, extraParams,
			"file", path, clientIp, []byte(""))

		keyChangeInput := &context.BeegoInput{Context: &context.Context{Request: keyRequest}}
		setParam(keyChangeInput)

		keyBeegoController := beego.Controller{Ctx: &context.Context{Input: keyChangeInput,
			Request: keyRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		keyController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: keyBeegoController}}

		//case-1
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return err
		})
		defer patch1.Reset()
		_, _, _, result := keyController.GetClientIpNew()
		assert.NotEmpty(t, result, "Error getting new Client IP")

		//case-2
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyFunc(util.ValidateUUID, func(id string) error {
			return err
		})
		defer patch3.Reset()
		_, _, _, result2 := keyController.GetClientIpNew()
		assert.NotEmpty(t, result2, "Error getting new Client IP")

		//case-1 for GetClientIp
		patch4 := gomonkey.ApplyFunc(util.ValidateUUID, func(id string) error {
			return nil
		})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyFunc(util.ValidateAccessToken, func(accessToken string,
			allowedRoles []string, tenantId string) error {
			return err
		})
		defer patch5.Reset()
		_, result3 := keyController.GetClientIp()
		assert.NotEmpty(t, result3, "Error getting Client IP")

		//case-1 for errorLog
		keyController.ErrorLog(clientIp, err, "not found")

		//case-2
		keyController.ErrorLog(clientIp, errors.New("not found"), "not found")
	})
}

func testDeletePkg(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestDeletePkg", func(_ *testing.T) {

		deleteRequest, _ := getHttpRequest(tenantsPath+tenantIdentifier+directory+packageId+hosts+ipAddress,
			extraParams, "file", path, clientIp, []byte(""))

		deleteChangeInput := &context.BeegoInput{Context: &context.Context{Request: deleteRequest}}
		setParam(deleteChangeInput)

		deleteBeegoController := beego.Controller{Ctx: &context.Context{Input: deleteChangeInput,
			Request: deleteRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		deleteController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: deleteBeegoController}}

		//case-1
		appPkgHostRecord := &models.AppPackageHostRecord{
			PkgHostKey: "pk",
			HostIp:     clientIp,
			Origin:     "mepm",
		}
		var appPkgRec models.AppPackageRecord
		appPkgRec.Origin = "mepm"

		accessToken := createToken(tenantIdentifier)
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch1.Reset()
		_ = deleteController.DeletePkg(appPkgHostRecord, clientIp, packageId, accessToken)

		//case-2
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch2.Reset()

		result2 := deleteController.DeletePkg(appPkgHostRecord, clientIp, packageId, accessToken)
		assert.NotEmpty(t, result2, "Error deleting package")

		//case-3
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch3.Reset()
		patch4 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, err
		})
		defer patch4.Reset()
		result3 := deleteController.DeletePkg(appPkgHostRecord, clientIp, packageId, accessToken)
		assert.NotEmpty(t, result3, "Error deleting package")

		//case-4
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch5.Reset()
		patch6 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, nil
		})
		defer patch6.Reset()

		//test case:1 for DeleteAppPkgRecords
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), "DeleteData",
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch7.Reset()
		result4 := deleteController.DeleteAppPkgRecords(packageId, "123", clientIp)
		assert.NotEmpty(t, result4, "Error deleting App package records")

		result6 := deleteController.DeleteAppPackageHostRecord(clientIp, packageId, "123")
		assert.NotEmpty(t, result6, "Error deleting App package host record")

		result7 := deleteController.DeleteAppInfoRecord("instId")
		assert.NotEmpty(t, result7, "Error deleting App Info record")

		//case-2
		patch8 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), "DeleteData",
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch8.Reset()
		patch9 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), "QueryCountForTable",
			func(_ *MockDb, _ string, _ string, _ string) (int64, error) {
				return 1, err
			})
		defer patch9.Reset()

		result5 := deleteController.DeleteAppPkgRecords(packageId, "123", clientIp)
		assert.NotEmpty(t, result5, "Error deleting App package records")

		//case-2
		patch10 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), "DeleteData",
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch10.Reset()
		patch11 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), "QueryCountForTable",
			func(_ *MockDb, _ string, _ string, _ string) (int64, error) {
				return 1, nil
			})
		defer patch11.Reset()

		result8 := deleteController.DeleteAppPkgRecords(packageId, "123", clientIp)
		assert.Empty(t, result8, "Error deleting App package records")
	})
}

func testTerminateApplication(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestTerminateApplication", func(t *testing.T) {

		terminateRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/hosts/1.1.1.1",
			extraParams, "file", "", deleteOper, []byte(""))

		terminateInput := &context.BeegoInput{Context: &context.Context{Request: terminateRequest}}
		setParam(terminateInput)

		terminateBeegoController := beego.Controller{Ctx: &context.Context{Input: terminateInput,
			Request: terminateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		terminateController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: terminateBeegoController}}

		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch1.Reset()

		var appInfoRecord models.AppInfoRecord
		appInfoRecord.AppInstanceId = "app_instance_id"

		_ = terminateController.TerminateApplication(clientIp, appInfoRecord.AppInstanceId)
		assert.Equal(t, 500, terminateController.Ctx.ResponseWriter.Status,
			"failed")

		//case-2
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch2.Reset()
		patch4 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, err
		})
		defer patch4.Reset()
		_ = terminateController.TerminateApplication(clientIp, appInfoRecord.AppInstanceId)
		assert.Equal(t, 500, terminateController.Ctx.ResponseWriter.Status,
			"Failed")

		//case-3
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch5.Reset()
		patch6 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, nil
		})
		defer patch6.Reset()
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController.Db), "DeleteData",
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch7.Reset()
		_ = terminateController.TerminateApplication(clientIp, appInfoRecord.AppInstanceId)
	})
}

func testAddMecHostErr(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestAddMecHost", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]string{
			"mechostName":    "edgegallery",
			"zipCode":        "560048",
			"city":           "xian",
			"affinity":       "shenzhen",
			"coordinates":    "1,2",
			originKey:        originVal,
			"hwcapabilities": hwcapabilities,
		})

		// Get Request
		mecHostRequest, _ := getHttpRequest(hostsPath, extraParams,
			packageName, "", "POST", requestBody)

		// Prepare Input
		mecHostInput := &context.BeegoInput{Context: &context.Context{
			Request: mecHostRequest}, RequestBody: requestBody}
		setParam(mecHostInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: mecHostInput,
			Request: mecHostRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test case-1
		instantiateController.AddMecHost()
		assert.Equal(t, 400, instantiateController.Ctx.ResponseWriter.Status, "Add MEC host failed")

		//case-2
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return err
		})
		defer patch1.Reset()
		instantiateController.AddMecHost()

		//case-3
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "ValidateAddMecHostRequest",
			func(_ *controllers.MecHostController, clientIp string, request models.MecHostInfo) error {
				return err
			})
		defer patch3.Reset()
		instantiateController.AddMecHost()

		mecHost := models.MecHostInfo{Hwcapabilities: []models.MecHwCapabilities{
			{
				HwType:   "testType",
				HwVendor: "testVendor",
				HwModel:  "testModel",
			},
		}}
		mecHost.MechostIp = clientIp
		mecHost.Origin = ""
		mecHost.ConfigUploadStatus = "updated"

		//mock for ValidateIpv4Address
		patch5 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(id string) error {
			return err
		})
		defer patch5.Reset()

		//mock for ValidateName with hostname error
		patch4 := gomonkey.ApplyFunc(util.ValidateName, func(name string, regex string) (bool, error) {
			return false, err
		})
		defer patch4.Reset()

		result := instantiateController.ValidateAddMecHostRequest(clientIp, mecHost)
		assert.NotEmpty(t, result, "Validate Add MecHost Request")

		result1 := instantiateController.ValidateMecHostZipCodeCity(mecHost, clientIp)
		assert.NotEmpty(t, result1, "Validate Add MecHost ZipCode City")

		//case-1
		result = instantiateController.InsertorUpdateMecHostRecord(clientIp, mecHost)
		assert.Empty(t, result, "error while Insert or Update MecHost Record")

		//case-2
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), "InsertOrUpdateData",
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch6.Reset()
		result = instantiateController.InsertorUpdateMecHostRecord(clientIp, mecHost)
		assert.NotEmpty(t, result, "error while Insert or Update MecHost Record")
	})
}

func testDeletePackageErr(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeletePackage", func(t *testing.T) {

		// POST Request
		instantiateRequest, _ := getHttpRequest(tenantsPath+
			tenantIdentifier+directory+
			packageId+hosts+ipAddress, extraParams,
			"file", "", deleteOper, []byte(""))

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest}}
		setParam(instantiateInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput,
			Request: instantiateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test instantiate
		instantiateController.DeletePackage()
	})
}

func testSyncUpdatedMecHostRec2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestSyncUpdatedMecHostRec", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest("https://edgegallery:8094/lcmcontroller/v1/tenants/hosts/sync_updated",
			extraParams, "file", path, "GET", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return errors.New("error")
		})
		defer patch1.Reset()
		// Test query
		queryController.SynchronizeMecHostUpdatedRecord()

		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, queryController.Ctx.ResponseWriter.Status, queryFailed)
		_ = queryController.Ctx.ResponseWriter.ResponseWriter.(*httptest.ResponseRecorder)

		queryController.SynchronizeMecHostStaleRecord()
	})
}

func testBatchTerminate2(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {
	t.Run("TestBatchTerminate", func(t *testing.T) {
		// POST Request
		batchTerminateRequest, _ := getHttpRequest(appUrlPath+"batchTerminate", extraParams,
			"file", "", "POST", []byte(""))

		requestBody, _ := json.Marshal(map[string]string{
			"appInstances":  appInstanceIdentifier,
			"appInstances2": "appInstanceIdentifier2",
		})

		// Prepare Input
		batchTerminateInput := &context.BeegoInput{Context: &context.Context{
			Request: batchTerminateRequest}, RequestBody: requestBody}
		setParam(batchTerminateInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: batchTerminateInput,
			Request: batchTerminateRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		patch2 := gomonkey.ApplyFunc(util.ValidateUUID, func(id string) error {
			return errors.New("error")
		})
		defer patch2.Reset()
		instantiateController.BatchTerminate()
		// Check for success case wherein the status value will be default i.e. 0
		assert.Equal(t, 400, instantiateController.Ctx.ResponseWriter.Status,
			"Batch terminate failed")
	})
}

func testUploadConfigV2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestConfigUploadV2", func(_ *testing.T) {

		// Get Request
		uploadRequest, _ := getHttpRequest(uploadConfigRequestV2, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		uploadInput := &context.BeegoInput{Context: &context.Context{Request: uploadRequest}}
		setParam(uploadInput)

		// Prepare beego controller
		uploadBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadInput, Request: uploadRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		uploadController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoController}}

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return err
		})
		defer patch1.Reset()

		// Test instantiate
		uploadController.UploadConfigV2()

		assert.Equal(t, 400, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")

		patch3 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch3.Reset()

		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(uploadController), "GetInputParametersForUploadCfg",
			func(_ *controllers.LcmControllerV2, clientIp string) (hostIp string,
				vim string, file multipart.File, err error) {
				return "", "nil", file, err
			})
		defer patch2.Reset()
	})
}

func testUploadConfig2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestConfigUploadV2", func(_ *testing.T) {

		// Get Request
		uploadRequest, _ := getHttpRequest(uploadConfigRequestV2, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		uploadInput := &context.BeegoInput{Context: &context.Context{Request: uploadRequest}}
		setParam(uploadInput)

		// Prepare beego controller
		uploadBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadInput, Request: uploadRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		uploadController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoController}}

		patch3 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch3.Reset()

		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(uploadController), "GetInputParametersForUploadCfg",
			func(_ *controllers.LcmControllerV2, clientIp string) (string, string, multipart.File, error) {
				return "", "nil", nil, errors.New("error")
			})
		defer patch2.Reset()

		// Test instantiate
		uploadController.UploadConfigV2()

		assert.Equal(t, 0, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")
	})
}

func testUploadConfig3(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestConfigUploadV2", func(_ *testing.T) {

		// Get Request
		uploadRequest, _ := getHttpRequest(uploadConfigRequestV2, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		uploadInput := &context.BeegoInput{Context: &context.Context{Request: uploadRequest}}
		setParam(uploadInput)

		// Prepare beego controller
		uploadBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadInput, Request: uploadRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		uploadController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoController}}

		patch3 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch3.Reset()

		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(uploadController), "GetInputParametersForUploadCfg",
			func(_ *controllers.LcmControllerV2, clientIp string) (string, string, multipart.File, error) {
				return "", "nil", nil, nil
			})
		defer patch2.Reset()

		patch4 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, err
		})
		defer patch4.Reset()
		uploadController.UploadConfigV2()
		assert.Equal(t, 404, uploadController.Ctx.ResponseWriter.Status, "Config upload failed")

	})
}

func testUploadPkgV2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestUploadPackage", func(t *testing.T) {

		// Get Request
		url := tenantsPathV2 + tenantIdentifier + packages
		uploadPkgRequest, _ := getHttpRequest(url, extraParams,
			packageName, path, "POST", []byte(""))

		// Prepare Input
		uploadPkgInput := &context.BeegoInput{Context: &context.Context{Request: uploadPkgRequest}}
		setParam(uploadPkgInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadPkgInput,
			Request: uploadPkgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return err
		})
		defer patch1.Reset()
		// Test upload package
		instantiateController.UploadPackageV2()
	})
}

func testUploadPkgV2Err(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestUploadPackage", func(t *testing.T) {

		// Get Request
		url := tenantsPathV2 + tenantIdentifier + packages
		uploadPkgRequest, _ := getHttpRequest(url, extraParams,
			packageName, path, "POST", []byte(""))

		// Prepare Input
		uploadPkgInput := &context.BeegoInput{Context: &context.Context{Request: uploadPkgRequest}}
		setParam(uploadPkgInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadPkgInput,
			Request: uploadPkgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		patch1 := gomonkey.ApplyFunc(util.ValidateFileExtensionCsar, func(fileName string) error {
			return err
		})
		defer patch1.Reset()
		// Test upload package
		instantiateController.UploadPackageV2()

		patch2 := gomonkey.ApplyFunc(util.ValidateName, func(name string, regex string) (bool, error) {
			return false, err
		})
		defer patch2.Reset()
		_, result := instantiateController.GetOrigin(clientIp)
		assert.NotEmpty(t, result, " failed to get origin")
	})
}

func testGetInputParametersForUploadCfg(t *testing.T, extraParams map[string]string, path string,
	testDb dbAdapter.Database) {

	t.Run("TestGetInputParametersForUploadCfg", func(_ *testing.T) {

		// Get Request
		uploadRequest, _ := getHttpRequest(uploadConfigRequestV2, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		uploadInput := &context.BeegoInput{Context: &context.Context{Request: uploadRequest}}
		setParam(uploadInput)

		// Prepare beego controller
		uploadBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadInput, Request: uploadRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		uploadController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoController}}

		patch3 := gomonkey.ApplyFunc(util.ValidateFileExtensionEmpty, func(fileName string) error {
			return err
		})
		defer patch3.Reset()

		// Test instantiate
		_, _, _, result := uploadController.GetInputParametersForUploadCfg(clientIp)
		assert.NotEmpty(t, result, "Get Input Parameters For Upload Cfg failed")
	})
}

func TestProcessAkSkConfig(t *testing.T) {

	instantiateReq := &models.InstantiateRequest{
		HostIp:     clientIp,
		PackageId:  "packageId",
		AppName:    "appname",
		Origin:     "origin",
		Parameters: map[string]string{"ak": "value1", "sk": "value2"},
		AkSkLcmGen: false,
	}
	result, _ := controllers.ProcessAkSkConfig("instID", "appName", instantiateReq,
		clientIp, "tenantId")
	assert.NotEmpty(t, result, " process Ak Sk Config")
}

func testGetPackageDetailsFromPackage(t *testing.T, extraParams map[string]string,
	path string, testDb dbAdapter.Database) {

	t.Run("TestGetPackageDetailsFromPackage", func(t *testing.T) {
		// Get Request
		url := tenantsPath + tenantIdentifier + packages
		uploadPkgRequest, _ := getHttpRequest(url, extraParams,
			packageName, path, "POST", []byte(""))

		// Prepare Input
		uploadPkgInput := &context.BeegoInput{Context: &context.Context{Request: uploadPkgRequest}}
		setParam(uploadPkgInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: uploadPkgInput,
			Request: uploadPkgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		patch10 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "GetFileContainsExtension",
			func(_ *controllers.LcmController, clientIp string, pkgDir string, ext string) (_ string, error error) {
				return "", nil
			})
		defer patch10.Reset()

		packageDir := "abc"
		_, result := instantiateController.GetPackageDetailsFromPackage(clientIp, packageDir)
		assert.NotEmpty(t, result, "failed to read mf fil")
	})
}

func testDistributionStatus1(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDistributionStatus", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string][]string{
			hostIpKey: {ipAddress},
		})
		// Get Request
		url := tenantsPathV2 + tenantIdentifier + packages + packageId
		distributePkgRequest, _ := getHttpRequest(url, extraParams,
			packageName, "", "POST", []byte(""))

		// Prepare Input
		distributePkgInput := &context.BeegoInput{Context: &context.Context{
			Request: distributePkgRequest}, RequestBody: requestBody}

		setParam(distributePkgInput)

		// Prepare beego controller
		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: distributePkgInput,
			Request: distributePkgRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		// Test instantiate
		instantiateController.DistributionStatus()

	})
}

func testSynchronizeAppPackageUpdatedRecord1(t *testing.T, extraParams map[string]string,
	path string, testDb dbAdapter.Database) {

	t.Run("TestSynchronizeAppPackageUpdatedRecord", func(t *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(tenantsPath+tenantIdentifier+"/packages/sync_updated", extraParams,
			"file", path, "GET", []byte(""))

		requestBody, _ := json.Marshal(map[string]string{
			"appInstances": appInstanceIdentifier,
		})

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}, RequestBody: requestBody}
		setParam(queryInput)

		// Prepare beego controller
		queryBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return err
		})
		defer patch1.Reset()
		// Test query
		queryController.SynchronizeAppPackageUpdatedRecord()

		patch2 := gomonkey.ApplyFunc(util.ValidateAccessToken,
			func(accessToken string, allowedRoles []string, tenantId string) error {
				return err
			})
		defer patch2.Reset()

		patch3 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch3.Reset()

		queryController.SynchronizeAppPackageUpdatedRecord()
		queryController.SynchronizeAppPackageStaleRecord()
		queryController.HandleLoggingForTokenFailure(clientIp, "forbidden")

		patch4 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, err
		})
		defer patch4.Reset()

		_, result := queryController.GetPluginAdapter("", clientIp, "vim")
		assert.NotEmpty(t, result, "failed to get plugin adapter")

		//case-2 for SynchronizeAppPackageUpdatedRecord
		patch5 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(id string) error {
			return nil
		})
		defer patch5.Reset()
		patch8 := gomonkey.ApplyFunc(util.ValidateUUID, func(id string) error {
			return errors.New("error")
		})
		defer patch8.Reset()
		queryController.SynchronizeAppPackageUpdatedRecord()
	})
}

func testAddMecHosts(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestAddMecHost", func(t *testing.T) {

		requestBody, _ := json.Marshal(map[string]string{
			"mechostIp":   ipAddress,
			"mechostName": "edgegallery",
			"zipCode":     "560048",
			"coordinates": "1,2",
			originKey:     originVal,
		})

		mecHostRequest, _ := getHttpRequest(hostsPath, extraParams,
			packageName, "", "POST", requestBody)

		mecHostInput := &context.BeegoInput{Context: &context.Context{
			Request: mecHostRequest}, RequestBody: requestBody}
		setParam(mecHostInput)

		instantiateBeegoController := beego.Controller{Ctx: &context.Context{Input: mecHostInput,
			Request: mecHostRequest, ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		baseController := &controllers.MecHostController{controllers.BaseController{Db: testDb,
			Controller: instantiateBeegoController}}

		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(baseController.Db), "QueryCount",
			func(_ *MockDb, _ string) (int64, error) {
				return 1, err
			})
		defer patch1.Reset()

		// for testing DeleteMecHost
		baseController.AddMecHost()
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(baseController.Db), "QueryCount",
			func(_ *MockDb, _ string) (int64, error) {
				return 1, err
			})
		defer patch2.Reset()
		baseController.DeleteMecHost()
		assert.NotEmpty(t, 400, baseController.Ctx.ResponseWriter.Status,
			"username is invalid")

		//case-2
		instantiateBeegoController.Ctx.Request.Header.Set("key", "testKey")
		patch9 := gomonkey.ApplyFunc(util.ValidateDbParams, func(_ string) (bool, error) {
			return false, err
		})
		defer patch9.Reset()
		baseController.AddMecHost()

		// for testing DeleteMecHost
		baseController.DeleteMecHost()
		assert.NotEmpty(t, 400, baseController.Ctx.ResponseWriter.Status,
			"key is invalid")

		//test case for DeleteHostInfoRecord
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(baseController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch5.Reset()
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(baseController.Db), "DeleteData",
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch7.Reset()
		result := baseController.DeleteHostInfoRecord(clientIp, "1.1.1.1")
		assert.NotEmpty(t, result, baseController.Ctx.ResponseWriter.Status,
			"delete is failed")

		//test case for GetAppInstance
		patch8 := gomonkey.ApplyFunc(util.ValidateUUID, func(id string) error {
			return errors.New("error")
		})
		defer patch8.Reset()
		baseController.GetAppInstance()
	})
}
