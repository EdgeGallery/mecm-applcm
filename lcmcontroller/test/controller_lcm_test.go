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
	"lcmcontroller/config"
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
	testUploadConfig3(t, extraParams, path, testDb)

	testUploadPkgV2(t, extraParams, path, testDb)
	testUploadPkgV2Err(t, extraParams, path, testDb)
	testGetInputParametersForUploadCfg(t, extraParams, path, testDb)

	testGetPackageDetailsFromPackage(t, extraParams, path, testDb)
	testDistributionStatus1(t, extraParams, testDb)
	testSynchronizeAppPackageUpdatedRecord1(t, extraParams, path, testDb)

	testAddMecHosts(t, extraParams, testDb)
	testDoPrepareParams(t, extraParams, path, testDb)
	testInsertOrUpdateAppInfoRecord(t, extraParams, path, testDb)
	testQueryV2(t, extraParams, path, testDb)
	testInsertOrUpdateAppPkgHostRecord(t, extraParams, path, testDb)
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
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		keyController.ChangeKey()

		//case-2
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), getInputParametersForChangeKey,
			func(_ *controllers.LcmController, _ string) (_ string, _ string, _ string, error error) {
				return username, "", "", err
			})
		defer patch3.Reset()
		keyController.ChangeKey()

		//case-3
		patch4 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), getInputParametersForChangeKey,
			func(_ *controllers.LcmController, _ string) (_ string, _ string, _ string, error error) {
				return username, "", "", nil
			})
		defer patch5.Reset()
		keyController.ChangeKey()

		//case-4
		patch6 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch6.Reset()
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), getInputParametersForChangeKey,
			func(_ *controllers.LcmController, _ string) (_ string, _ string, _ string, error error) {
				return username, "testKey4", "", nil
			})
		defer patch7.Reset()
		patch8:= gomonkey.ApplyMethod(reflect.TypeOf(keyController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch8.Reset()
		keyController.ChangeKey()

		patch9:= gomonkey.ApplyMethod(reflect.TypeOf(keyController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch9.Reset()
		patch10 := gomonkey.ApplyMethod(reflect.TypeOf(keyController.Db), insertOrUpdateData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch10.Reset()
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
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), getUserName,
			func(_ *controllers.LcmController, _ string) (_ string, error error) {
				return username, err
			})
		defer patch1.Reset()
		_, _, _, result := keyController.GetInputParametersForChangeKey(clientIp)
		assert.NotEmpty(t, result, "Error getting username Parameter For upload")

		//test case:1 for validatetoken
		instantiateReq := models.InstantiateRequest{
			HostIp:     clientIp,
			PackageId:  packageId,
			AppName:    "appname1",
			Origin:     originVal,
			Parameters: map[string]string{"ak": "value11", "sk": "value22"},
			AkSkLcmGen: false,
		}
		_, _, _, _, _, _ = keyController.ValidateToken("token3", instantiateReq, clientIp)
		keyController.AppDeploymentStatus()

		//test case:1 for GetClientIpAndValidateAccessToken
		_, _, _, clientResult := keyController.GetClientIpAndValidateAccessToken("msg",
			[]string{tenantRole, adminRole}, tenantIdentifier)
		assert.NotEmpty(t, clientResult, "Error getting client ip and validating token")

		//case-3
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), getUserName,
			func(_ *controllers.LcmController, _ string) (_ string, error error) {
				return username, nil
			})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetKey",
			func(_ *controllers.LcmController, _ string) (_ string, error error) {
				return "testKey5", err
			})
		defer patch3.Reset()
		_, _, _, result2 := keyController.GetInputParametersForChangeKey(clientIp)
		assert.NotEmpty(t, result2, "Error getting key Parameter For upload")

		//test case-2 for validateToken
		_, _, _, _, _, _ = keyController.ValidateToken("token4", instantiateReq, clientIp)
		keyController.AppDeploymentStatus()

		//test case:2 for GetClientIpAndValidateAccessToken
		_, _, _, clientResult2 := keyController.GetClientIpAndValidateAccessToken("msg",
			[]string{tenantRole, adminRole}, tenantIdentifier)
		assert.NotEmpty(t, clientResult2, "Error getting client ip and validating access token failed")

		//case-4
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), getUserName,
			func(_ *controllers.LcmController, _ string) (_ string, error error) {
				return username, nil
			})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetKey",
			func(_ *controllers.LcmController, _ string) (_ string, error error) {
				return "testKey1", nil
			})
		defer patch5.Reset()
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), "GetNewKey",
			func(_ *controllers.LcmController, _ string) (_ string, error error) {
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
			[]string{tenantRole, adminRole}, tenantIdentifier)
		assert.NotEmpty(t, clientResult3, "Error getting client ip as failed to validating access token")

		//test case-3 for validateToken
		patch12 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return err
		})
		defer patch12.Reset()
		_, _, _, _, _, _ = keyController.ValidateToken("token5", instantiateReq, clientIp)

		//test case-4 for validateToken
		patch13 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return nil
		})
		defer patch13.Reset()

		patch14 := gomonkey.ApplyFunc(util.ValidateAccessToken, func(_ string,
			_ []string, _ string) error {
			return err
		})
		defer patch14.Reset()
		_, _, _, _, _, _ = keyController.ValidateToken("token6", instantiateReq, clientIp)
		keyController.AppDeploymentStatus()
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
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		keyController.LoginPage()

		//test case:4 for GetClientIpAndValidateAccessToken
		_, _, _, result := keyController.GetClientIpAndValidateAccessToken("msg",
			[]string{tenantRole, adminRole}, tenantIdentifier)
		assert.NotEmpty(t, result, "Error getting client ip and validating access token")

		//test case:1 for GetClientIpAndValidateAccessToken
		_, _, _, _, result5 := keyController.GetClientIpAndIsPermitted("msg")
		assert.NotEmpty(t, result5, "Error getting client ip and permission")

		//case-2
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), getInputParametersForChangeKey,
			func(_ *controllers.LcmController, _ string) (_ string, _ string, _ string, error error) {
				return username, "", "", err
			})
		defer patch3.Reset()
		keyController.LoginPage()

		//case-3
		patch4 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), getInputParametersForChangeKey,
			func(_ *controllers.LcmController, _ string) (_ string, _ string, _ string, error error) {
				return username, "", "", nil
			})
		defer patch5.Reset()
		keyController.LoginPage()

		//case-4
		patch6 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch6.Reset()
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(keyController), getInputParametersForChangeKey,
			func(_ *controllers.LcmController, _ string) (_ string, _ string, _ string, error error) {
				return username, "testKey2", "", nil
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
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		_, _, _, result := keyController.GetClientIpNew()
		assert.NotEmpty(t, result, "Error getting new Client IP")

		//case-2
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return err
		})
		defer patch3.Reset()
		_, _, _, result2 := keyController.GetClientIpNew()
		assert.NotEmpty(t, result2, "Error getting new Client IP")

		//case-1 for GetClientIp
		patch4 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return nil
		})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyFunc(util.ValidateAccessToken, func(_ string,
			_ []string, _ string) error {
			return err
		})
		defer patch5.Reset()
		_, result3 := keyController.GetClientIp()
		assert.NotEmpty(t, result3, "Error getting Client IP")

		//case-1 for errorLog
		keyController.ErrorLog(clientIp, err, "notFound")

		//case-2
		keyController.ErrorLog(clientIp, errors.New(errorNotFond), "404")
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

		deleteLcmv2Controller := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
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

		//test case-1 for deletepkg of LcmV2Controller
		result := deleteLcmv2Controller.DeletePkg(appPkgHostRecord, clientIp, packageId, accessToken)
		assert.Empty(t, result, "deleted package for lcmv2 controller successfully")


		//case-2
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch2.Reset()

		result2 := deleteController.DeletePkg(appPkgHostRecord, clientIp, packageId, accessToken)
		assert.NotEmpty(t, result2, "Error deleting package")

		//test case-2 for deletepkg of LcmV2Controller
		resultv2 := deleteLcmv2Controller.DeletePkg(appPkgHostRecord, clientIp, packageId, accessToken)
		assert.NotEmpty(t, resultv2, "Error deleting package for lcmv2 controller")

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

		//test case-3 for deletepkg of LcmV2Controller
		result2v2 := deleteLcmv2Controller.DeletePkg(appPkgHostRecord, clientIp, packageId, accessToken)
		assert.NotEmpty(t, result2v2, "Error deleting package at getclient")

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
		patch17 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), deleteData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch17.Reset()
		result4 := deleteController.DeleteAppPkgRecords(packageId, tenantIdentifier, clientIp)
		assert.NotEmpty(t, result4, "Error on deleting App package records")

		result6 := deleteController.DeleteAppPackageHostRecord(clientIp, packageId, tenantIdentifier)
		assert.NotEmpty(t, result6, "Error deleting App package host record")

		result7 := deleteController.DeleteAppInfoRecord("instId")
		assert.NotEmpty(t, result7, "Error deleting App Info record")

		//test case-1 for DeleteAppPkgRecords of LcmControllerv2
		_ = deleteLcmv2Controller.DeleteAppPkgRecords(packageId, tenantIdentifier, clientIp)

		//case-2
		patch8 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), deleteData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch8.Reset()
		patch9 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), queryCountForTable,
			func(_ *MockDb, _ string, _ string, _ string) (int64, error) {
				return 1, err
			})
		defer patch9.Reset()

		result5 := deleteController.DeleteAppPkgRecords(packageId, tenantIdentifier, clientIp)
		assert.NotEmpty(t, result5, "Error deleting Application package records")

		//test case-2 for DeleteAppPkgRecords of LcmControllerv2
		_ = deleteLcmv2Controller.DeleteAppPkgRecords(packageId, tenantIdentifier, clientIp)

		//case-2
		patch10 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), deleteData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch10.Reset()
		patch11 := gomonkey.ApplyMethod(reflect.TypeOf(deleteController.Db), queryCountForTable,
			func(_ *MockDb, _ string, _ string, _ string) (int64, error) {
				return 1, nil
			})
		defer patch11.Reset()

		result8 := deleteController.DeleteAppPkgRecords(packageId, tenantIdentifier, clientIp)
		assert.Empty(t, result8, "Error deleting App package records")

		//test case for getInputParametersForRemoveCfg
		patch12 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return err
		})
		defer patch12.Reset()
		_, _, _, result10 := deleteLcmv2Controller.GetInputParametersForRemoveCfg(clientIp)
		assert.NotEmpty(t, result10, "Error occurred as host does not exist ")

		//case-2:
		patch13 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return nil
		})
		defer patch13.Reset()
		patch16 := gomonkey.ApplyMethod(reflect.TypeOf(deleteLcmv2Controller.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch16.Reset()
		_, _, _, result11 := deleteLcmv2Controller.GetInputParametersForRemoveCfg(clientIp)
		assert.Empty(t, result11, "Error occurred as host does not exist ")
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
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(terminateController.Db), deleteData,
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
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		instantiateController.AddMecHost()

		//case-3
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController), "ValidateAddMecHostRequest",
			func(_ *controllers.MecHostController, _ string, _ models.MecHostInfo) error {
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
		patch5 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return err
		})
		defer patch5.Reset()

		//mock for ValidateName with hostname error
		patch4 := gomonkey.ApplyFunc(util.ValidateName, func(_ string, _ string) (bool, error) {
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
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), insertOrUpdateData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch6.Reset()
		result = instantiateController.InsertorUpdateMecHostRecord(clientIp, mecHost)
		assert.NotEmpty(t, result, "error while Insert or Update MecHost Record")
	})
}

func testDeletePackageErr(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDeletePackage", func(_ *testing.T) {

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

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
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

		patch2 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
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
		uploadControllerLcmV2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoController}}

		uploadController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoController}}

		//case-1
		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		uploadControllerLcmV2.UploadConfigV2()
		assert.Equal(t, 400, uploadControllerLcmV2.Ctx.ResponseWriter.Status, "Config upload is failed")


		//case-2
		patch3 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch3.Reset()
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(uploadControllerLcmV2), getInputParametersForUploadCfg,
			func(_ *controllers.LcmControllerV2, _ string) (hostIp string,
				vim string, file multipart.File, err error) {
				return "", "nil", file, err
			})
		defer patch2.Reset()
		uploadControllerLcmV2.UploadConfigV2()
		assert.Equal(t, 400, uploadControllerLcmV2.Ctx.ResponseWriter.Status, "Config upload failed error")

		//test case-1 for UploadConfig of lcmController
		uploadController.UploadConfig()
		assert.Equal(t, 400, uploadController.Ctx.ResponseWriter.Status, "Config upload failed for lcmv2")


		//case-3
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(uploadControllerLcmV2), getInputParametersForUploadCfg,
			func(_ *controllers.LcmControllerV2, _ string) (string, string, multipart.File, error) {
				return "", "nil", nil, nil
			})
		defer patch7.Reset()
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(uploadControllerLcmV2.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch5.Reset()
		uploadControllerLcmV2.UploadConfigV2()
		assert.Equal(t, 400, uploadControllerLcmV2.Ctx.ResponseWriter.Status,
			"Config upload failed while reading data from db")

		//test case-2 for UploadConfig of lcmController
		uploadController.UploadConfig()
		assert.Equal(t, 400, uploadController.Ctx.ResponseWriter.Status,
			"Config upload failed for lcm")

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

		// Create LCM controllerV2 with mocked DB and prepared Beego controller
		uploadControllerLcmV2 := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoController}}

		//controller for lcm controller
		uploadController := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: uploadBeegoController}}

		//case-1
		patch3 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch3.Reset()
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(uploadControllerLcmV2), getInputParametersForUploadCfg,
			func(_ *controllers.LcmControllerV2, _ string) (string, string, multipart.File, error) {
				return "", "nil", nil, nil
			})
		defer patch2.Reset()
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(uploadControllerLcmV2.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch1.Reset()
		patch4 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, err
		})
		defer patch4.Reset()
		uploadControllerLcmV2.UploadConfigV2()
		assert.Equal(t, 500, uploadControllerLcmV2.Ctx.ResponseWriter.Status,
			"Config upload failed for plugin adapter")

		patch11 := gomonkey.ApplyMethod(reflect.TypeOf(uploadControllerLcmV2), isPermitted	,
			func(_ *controllers.LcmControllerV2 , _, _ string) (string, error) {
			return  "", nil
		})
		defer patch11.Reset()
		//test case-2 for UploadConfig of lcmController
		uploadController.UploadConfig()
		assert.Equal(t, 500, uploadController.Ctx.ResponseWriter.Status,
			"Config upload is failed for lcm for plugin adapter")


		//case-2
		patch8 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch8.Reset()
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(uploadControllerLcmV2), getInputParametersForUploadCfg,
			func(_ *controllers.LcmControllerV2, _ string) (string, string, multipart.File, error) {
				return "", "nil", nil, nil
			})
		defer patch5.Reset()
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(uploadControllerLcmV2.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch6.Reset()
		patch7 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, nil
		})
		defer patch7.Reset()
		patch14 := gomonkey.ApplyMethod(reflect.TypeOf(uploadControllerLcmV2), isPermitted, func(_ *controllers.LcmControllerV2 , _, _ string) (string, error) {
			return  "", nil
		})
		defer patch14.Reset()

		patch10 := gomonkey.ApplyMethod(reflect.TypeOf(uploadControllerLcmV2.Db), insertOrUpdateData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch10.Reset()
		uploadControllerLcmV2.UploadConfigV2()
		assert.Equal(t, 500, uploadControllerLcmV2.Ctx.ResponseWriter.Status,
			"Config upload failed while inserting data")
	})
}

func testUploadPkgV2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestUploadPackage", func(_ *testing.T) {

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

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
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

		patch1 := gomonkey.ApplyFunc(util.ValidateFileExtensionCsar, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		// Test upload package
		instantiateController.UploadPackageV2()

		//test case for getOrigin
		patch2 := gomonkey.ApplyFunc(util.ValidateName, func(_ string, _ string) (bool, error) {
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

		//case-1:
		_, _, _, result := uploadController.GetInputParametersForUploadCfg(clientIp)
		assert.NotEmpty(t, result, "error getting Input Parameters For Upload Cfg failed")

		//case-2:
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(uploadController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch1.Reset()
		patch3 := gomonkey.ApplyFunc(util.ValidateFileExtensionEmpty, func(_ string) error {
			return err
		})
		defer patch3.Reset()
		_, _, _, result2 := uploadController.GetInputParametersForUploadCfg(clientIp)
		assert.Nil(t, result2, "error")

		//case-3
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(uploadController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch2.Reset()
		patch4:= gomonkey.ApplyFunc(util.ValidateFileExtensionEmpty, func(_ string) error {
			return nil
		})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return err
		})
		defer patch5.Reset()
		_, _, _, result3 := uploadController.GetInputParametersForUploadCfg(clientIp)
		assert.NotEmpty(t, result3, "error getting Input Parameter")
	})
}

func TestProcessAkSkConfig(t *testing.T) {

	instantiateReq := &models.InstantiateRequest{
		HostIp:     clientIp,
		PackageId:  packageId,
		AppName:    "appname2",
		Origin:     originVal,
		Parameters: map[string]string{"ak": "value1", "sk": "value2"},
		AkSkLcmGen: false,
	}
	result, _ := controllers.ProcessAkSkConfig("instID", "appName2", instantiateReq,
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
			func(_ *controllers.LcmController, _ string, _ string, _ string) (_ string, error error) {
				return "", nil
			})
		defer patch10.Reset()

		packageDir := "abc"
		_, result := instantiateController.GetPackageDetailsFromPackage(clientIp, packageDir)
		assert.NotEmpty(t, result, "failed to read mf fil")
	})
}

func testDistributionStatus1(t *testing.T, extraParams map[string]string, testDb dbAdapter.Database) {

	t.Run("TestDistributionStatus", func(_ *testing.T) {

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

		queryController2 := &controllers.LcmController{controllers.BaseController{Db: testDb,
			Controller: queryBeegoController}}

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		// Test query
		queryController.SynchronizeAppPackageUpdatedRecord()
		queryController2.AppDeploymentStatus()

		patch2 := gomonkey.ApplyFunc(util.ValidateAccessToken,
			func(_ string, _ []string, _ string) error {
				return err
			})
		defer patch2.Reset()

		patch3 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch3.Reset()

		queryController.SynchronizeAppPackageUpdatedRecord()
		queryController.SynchronizeAppPackageStaleRecord()
		queryController.HandleLoggingForTokenFailure(clientIp, "forbidden")
		queryController2.AppDeploymentStatus()

		patch4 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, err
		})
		defer patch4.Reset()

		_, result := queryController.GetPluginAdapter("", clientIp, "vim")
		assert.NotEmpty(t, result, "failed to get plugin adapter")

		//test case for DeletePackageOnHost of lcmControllerV2
		patch13 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch13.Reset()
		patch14 := gomonkey.ApplyFunc(util.ValidateAccessToken, func(_ string,
			_ []string, _ string) error {
			return nil
		})
		defer patch14.Reset()
		patch5 := gomonkey.ApplyMethod(reflect.TypeOf(queryController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch5.Reset()
		queryController.DeletePackageOnHost()

		//case-2 for SynchronizeAppPackageUpdatedRecord
		patch15 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch15.Reset()
		patch8 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return err
		})
		defer patch8.Reset()
		queryController.SynchronizeAppPackageUpdatedRecord()

		_, _, _, result2 := queryController.GetInputParametersForUploadPkg(clientIp)
		assert.NotEmpty(t, result2, "failed to get input parameters")
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

		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(baseController.Db), queryCount,
			func(_ *MockDb, _ string) (int64, error) {
				return 1, err
			})
		defer patch1.Reset()

		// for testing DeleteMecHost
		baseController.AddMecHost()
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(baseController.Db), queryCount,
			func(_ *MockDb, _ string) (int64, error) {
				return 1, err
			})
		defer patch2.Reset()
		baseController.DeleteMecHost()
		assert.NotEmpty(t, 400, baseController.Ctx.ResponseWriter.Status,
			"username is invalid")

		//case-2
		instantiateBeegoController.Ctx.Request.Header.Set("key", "testKey3")
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
		patch7 := gomonkey.ApplyMethod(reflect.TypeOf(baseController.Db), deleteData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch7.Reset()
		result := baseController.DeleteHostInfoRecord(clientIp, hostIp)
		assert.NotEmpty(t, result, baseController.Ctx.ResponseWriter.Status,
			"delete is failed")

		//test case for GetAppInstance
		patch8 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return err
		})
		defer patch8.Reset()
		baseController.GetAppInstance()
	})
}

func testDoPrepareParams(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestDoPrepareParams", func(_ *testing.T) {

		// Get Request
		initializeRequest, _ := getHttpRequest(uploadConfigRequestV2, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		initializeInput := &context.BeegoInput{Context: &context.Context{Request: initializeRequest}}
		setParam(initializeInput)

		// Prepare beego controller
		initializeBeegoController := beego.Controller{Ctx: &context.Context{Input: initializeInput, Request: initializeRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		initializeController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: initializeBeegoController}}
		params := &models.AppInfoParams{
			AppInstanceId: appInstanceIdentifier,
			TenantId:      tenantIdentifier,
			AppName:       "testApp",
			Origin:        originVal,
			AppPackageId:  packageId,
			ClientIP:      clientIp,
		}
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch1.Reset()
		controllers.DoPrepareParams(initializeController, params, nil)

		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch2.Reset()
		controllers.DoPrepareParams(initializeController, params, nil)

		//test case for DoInstantiate
		instantiateReq := models.InstantiateRequest{
			HostIp:     clientIp,
			PackageId:  packageId,
			AppName:    "appname3",
			Origin:     originVal,
			Parameters: map[string]string{"ak": "value2", "sk": "value3"},
			AkSkLcmGen: false,
		}
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch3.Reset()
		controllers.DoInstantiate(initializeController, params, nil, instantiateReq)

		//case-2:
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, err
		})
		defer patch5.Reset()
		controllers.DoInstantiate(initializeController, params, nil, instantiateReq)

		patch8 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), queryCount,
			func(_ *MockDb, _ string) (int64, error) {
				return 1, err
			})
		defer patch8.Reset()
		initializeController.InstantiateV2()

		//testcase for ValidateInstantiateInputParameters
		patch9 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return err
		})
		defer patch9.Reset()
		_, _, _, _, _, result1 := initializeController.ValidateInstantiateInputParameters(clientIp, instantiateReq)
		assert.NotEmpty(t, result1, "error while validating ip address")

		//test case for ValidateDistributeInputParameters
		distributeRequest := models.DistributeRequest{
			HostIp: []string{hostIp, clientIp},
			Origin: originVal,
		}
		_, result10 := initializeController.ValidateDistributeInputParameters(clientIp, distributeRequest)
		assert.NotEmpty(t, result10, "error while validating ipv4 address")

		initializeController.GetUrlHostIP(clientIp)
		//case2:
		patch10 := gomonkey.ApplyFunc(util.ValidateIpv4Address, func(_ string) error {
			return nil
		})
		defer patch10.Reset()
		instantiateReq2 := models.InstantiateRequest{
			HostIp:     clientIp,
			PackageId:  "",
		}
		_, _, _, _, _, result2 := initializeController.ValidateInstantiateInputParameters(clientIp, instantiateReq2)
		assert.Empty(t, result2, "package id length is 0")

		//test case-2 for ValidateDistributeInputParameters
		_, result11 := initializeController.ValidateDistributeInputParameters(clientIp, distributeRequest)
		assert.Empty(t, result11, "error as package id length is 0")

		//case4:
		instantiateReq3 := models.InstantiateRequest{
			HostIp:     clientIp,
			PackageId:  "e261211d80d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98e261211d80" +
				"d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98",
		}
		_, _, _, _, _, result3 := initializeController.ValidateInstantiateInputParameters(clientIp, instantiateReq3)
		assert.NotEmpty(t, result3, "package id length is >64")

		//case5:
		patch11 := gomonkey.ApplyFunc(util.ValidateName, func(_ string, _ string) (bool, error) {
			return false, err
		})
		defer patch11.Reset()
		_, _, _, _, _, result4 := initializeController.ValidateInstantiateInputParameters(clientIp, instantiateReq)
		assert.NotEmpty(t, result4, "Error while validating name")

		//test case-3 for ValidateDistributeInputParameters
		_, result12 := initializeController.ValidateDistributeInputParameters(clientIp, distributeRequest)
		assert.NotEmpty(t, result12, "error as validating failed")

		//case5:
		patch12 := gomonkey.ApplyFunc(util.ValidateName, func(_ string, _ string) (bool, error) {
			return true, nil
		})
		defer patch12.Reset()
		patch13 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return err
		})
		defer patch13.Reset()
		_, _, _, _, _, result5 := initializeController.ValidateInstantiateInputParameters(clientIp, instantiateReq)
		assert.NotEmpty(t, result5, "error while validating UUID")


	})
}

func testInsertOrUpdateAppInfoRecord(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestInsertOrUpdateAppInfoRecord", func(_ *testing.T) {

		// Get Request
		initializeRequest, _ := getHttpRequest(uploadConfigRequestV2, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		initializeInput := &context.BeegoInput{Context: &context.Context{Request: initializeRequest}}
		setParam(initializeInput)

		// Prepare beego controller
		initializeBeegoController := beego.Controller{Ctx: &context.Context{Input: initializeInput, Request: initializeRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		initializeController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: initializeBeegoController}}
		appInfoParams := models.AppInfoRecord{
			AppInstanceId: appInstanceIdentifier,
			TenantId:      tenantIdentifier,
			AppName:       "testApp",
			Origin:        "",
			AppPackageId:  packageId,
		}
		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch1.Reset()

		result := initializeController.InsertOrUpdateAppInfoRecord(clientIp, appInfoParams)
		assert.NotEmpty(t, result, "mechost not found error")

		//case-2
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch2.Reset()
		patch9 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), queryCountForTable,
			func(_ *MockDb, _ string, _ string, _ string) (int64, error) {
				return 1, err
			})
		defer patch9.Reset()
		result2 := initializeController.InsertOrUpdateAppInfoRecord(clientIp, appInfoParams)
		assert.NotEmpty(t, result2, "insert or update app info failed")

		//case-3
		patch4 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), queryCountForTable,
			func(_ *MockDb, _ string, _ string, _ string) (int64, error) {
				return 1, nil
			})
		defer patch4.Reset()
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), insertOrUpdateData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch6.Reset()
		result3 := initializeController.InsertOrUpdateAppInfoRecord(clientIp, appInfoParams)
		assert.NotEmpty(t, result3, "insert or update app data failed")

		//test case for InsertOrUpdateAppPkgRecord
		pkgdetails := models.AppPkgDetails{
			App_product_name: "testProduct",
		}
		result4 := initializeController.InsertOrUpdateAppPkgRecord("appId", clientIp, tenantIdentifier,
			packageId, pkgdetails, originVal)
		assert.NotEmpty(t, result4, "insert or update app pkg record failed")

		//test case for handleErrorForInstantiateApp
		config := config.AppConfigAdapter{
			AppAuthCfg: config.AppAuthConfig{},
			AppInfo:    config.AppInfo{},
		}
		initializeController.HandleErrorForInstantiateApp(config, clientIp, "instanceId", tenantIdentifier)

		//test case-1 for Terminatev2
		initializeController.TerminateV2()

		//test case-2 for Terminatev2
		patch5 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch5.Reset()
		initializeController.TerminateV2()

		//test case-3 for Terminatev2
		patch7 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch7.Reset()
		patch11 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController), isPermitted, func(_ *controllers.LcmControllerV2 , _, _ string) (string, error) {
			return  "", nil
		})
		defer patch11.Reset()
		patch8 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch8.Reset()
		initializeController.TerminateV2()

		//test case for ProcessUploadPackage
		distributeRequest := models.DistributeRequest{
			HostIp: []string{hostIp, clientIp},
			Origin: originVal,
		}
		_ = initializeController.ProcessUploadPackage(distributeRequest, clientIp, tenantIdentifier, packageId, "token2")

		//test case-4 for Terminatev2
		patch10 := gomonkey.ApplyMethod(reflect.TypeOf(initializeController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch10.Reset()
		patch12 := gomonkey.ApplyFunc(pluginAdapter.GetClient, func(_ string) (pluginAdapter.ClientIntf, error) {
			return &mockClient{}, err
		})
		defer patch12.Reset()
		initializeController.TerminateV2()

		//test case-2 for ProcessUploadPackage
		_ = initializeController.ProcessUploadPackage(distributeRequest, clientIp, tenantIdentifier, packageId, "token2")

		//test case for HandleLoggingForFailure
		initializeController.HandleLoggingForFailure(clientIp, "forbidden")
		initializeController.HandleLoggingForFailure(clientIp, "accessToken is invalid")
		initializeController.HandleLoggingForFailure(clientIp, errorNotFond)
	})
}

func testQueryV2(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestQueryV2", func(_ *testing.T) {

		// Get Request
		queryRequest, _ := getHttpRequest(uploadConfigRequestV2, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		queryInput := &context.BeegoInput{Context: &context.Context{Request: queryRequest}}
		setParam(queryInput)

		// Prepare beego controller
		initializeBeegoController := beego.Controller{Ctx: &context.Context{Input: queryInput, Request: queryRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		queryController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: initializeBeegoController}}

		patch1 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return err
		})
		defer patch1.Reset()
		queryController.QueryV2()
		_, _, _, result := queryController.GetClientIpNew()
		assert.NotEmpty(t, result, "insert or update app data failed")

		queryController.QueryKPI()
		queryController.GetWorkloadDescription()
		queryController.SynchronizeStaleRecord()
		queryController.SynchronizeUpdatedRecord()
		_, _, _, _ = queryController.GetClientIpAndValidateAccessToken("msg", []string{"s1", "s2"}, tenantIdentifier)
		_, _, _, _, result7 := queryController.GetClientIpAndIsPermitted("message")
		assert.NotEmpty(t, result7, "insert or update app data failed")

		//case-2
		patch2 := gomonkey.ApplyFunc(util.ValidateSrcAddress, func(_ string) error {
			return nil
		})
		defer patch2.Reset()
		patch3 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return err
		})
		defer patch3.Reset()
		queryController.QueryV2()
		_, _, _, result2 := queryController.GetClientIpNew()
		assert.NotEmpty(t, result2, "insert or update app data failed")
		queryController.SynchronizeStaleRecord()
		queryController.GetWorkloadDescription()
		queryController.SynchronizeUpdatedRecord()
		queryController.DeletePackage()
		//case-3
		patch4 := gomonkey.ApplyFunc(util.ValidateUUID, func(_ string) error {
			return nil
		})
		defer patch4.Reset()
		patch5 := gomonkey.ApplyFunc(util.ValidateAccessToken, func(_ string,
			_ []string, _ string) error {
			return err
		})
		defer patch5.Reset()
		queryController.QueryV2()
		queryController.QueryKPI()
		queryController.HandleKPI(clientIp, errors.New(errorNotFond), "404")
		queryController.HandleKPI(clientIp, errors.New("internal server error"), "500")
		queryController.SynchronizeStaleRecord()
		queryController.GetWorkloadDescription()
		queryController.SynchronizeUpdatedRecord()
		_, _, _, _ = queryController.GetClientIpAndValidateAccessToken("msg", []string{"s1", "s2"}, tenantIdentifier)


		// test case for GetUrlCapabilityId
		patch6 := gomonkey.ApplyFunc(util.ValidateMepCapabilityId, func(_ string) error {
			return err
		})
		defer patch6.Reset()
		_, result3 := queryController.GetUrlCapabilityId(clientIp)
		assert.Empty(t, result3, "error while getting url id")

		patch11 := gomonkey.ApplyMethod(reflect.TypeOf(queryController), isPermitted,
			func(_ *controllers.LcmControllerV2 , _, _ string) (string, error) {
			return  "", err
		})
		defer patch11.Reset()
		_, _, _, _, result8 := queryController.GetClientIpAndIsPermitted("message")
		assert.NotEmpty(t, result8, "insert or update app data failed")

		//test case for UpdateAppPkgRecord
		patch12 := gomonkey.ApplyMethod(reflect.TypeOf(queryController.Db), queryCount,
			func(_ *MockDb, _ string) (int64, error) {
				return 1, err
			})
		defer patch12.Reset()
		distributeRequest := models.DistributeRequest{
			HostIp: []string{"2.1.2.1", clientIp},
			Origin: originVal,
		}
		_ = queryController.UpdateAppPkgRecord(distributeRequest, clientIp, tenantIdentifier, packageId, hostIp, SUCCESS_RETURN)

		//test case-2 for UpdateAppPkgRecord
		patch13 := gomonkey.ApplyMethod(reflect.TypeOf(queryController.Db), queryCount,
			func(_ *MockDb, _ string) (int64, error) {
				return 1, nil
			})
		defer patch13.Reset()
		patch14 := gomonkey.ApplyFunc(util.ValidateName, func(_ string, _ string) (bool, error) {
			return false, err
		})
		defer patch14.Reset()
		_ = queryController.UpdateAppPkgRecord(distributeRequest, clientIp, tenantIdentifier, packageId, hostIp, SUCCESS_RETURN)
	})
}


func testInsertOrUpdateAppPkgHostRecord(t *testing.T, extraParams map[string]string, path string, testDb dbAdapter.Database) {

	t.Run("TestInsertOrUpdateAppPkgHostRecord", func(_ *testing.T) {

		// Get Request
		instantiateRequest, _ := getHttpRequest(uploadConfigRequestV2, extraParams,
			configfile, path, "POST", []byte(""))

		// Prepare Input
		instantiateInput := &context.BeegoInput{Context: &context.Context{Request: instantiateRequest}}
		setParam(instantiateInput)

		// Prepare beego controller
		initializeBeegoController := beego.Controller{Ctx: &context.Context{Input: instantiateInput, Request: instantiateRequest,
			ResponseWriter: &context.Response{ResponseWriter: httptest.NewRecorder()}},
			Data: make(map[interface{}]interface{})}

		// Create LCM controller with mocked DB and prepared Beego controller
		instantiateController := &controllers.LcmControllerV2{controllers.BaseController{Db: testDb,
			Controller: initializeBeegoController}}

		patch1 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), readData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return nil
			})
		defer patch1.Reset()
		patch2 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), queryCountForTable,
			func(_ *MockDb, _ string, _ string, _ string) (int64, error) {
				return 1, err
			})
		defer patch2.Reset()

		//test case for InsertOrUpdateAppPkgHostRecord
		result1 := instantiateController.InsertOrUpdateAppPkgHostRecord(hostIp, clientIp, tenantIdentifier, packageId,
			"distributed", "MEPM")
		assert.NotEmpty(t, result1, "insert or update app pkg failed")

		_ = instantiateController.DelAppPkgRecords(clientIp, packageId, tenantIdentifier, clientIp)

		//case-2
		patch3 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), queryCountForTable,
			func(_ *MockDb, _ string, _ string, _ string) (int64, error) {
				return 1, nil
			})
		defer patch3.Reset()
		patch6 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), insertOrUpdateData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch6.Reset()
		result := instantiateController.InsertOrUpdateAppPkgHostRecord(hostIp, clientIp, tenantIdentifier, packageId,
			"pending", "MEPM")
		assert.NotEmpty(t, result, "insert or update app pkg host failed")

		//test case for
		patch17 := gomonkey.ApplyMethod(reflect.TypeOf(instantiateController.Db), deleteData,
			func(_ *MockDb, _ interface{}, _ ...string) error {
				return err
			})
		defer patch17.Reset()
		_ = instantiateController.DelAppPkgRecords(clientIp, packageId, tenantIdentifier, clientIp)
	})
}