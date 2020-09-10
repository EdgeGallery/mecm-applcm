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
	_ "crypto/tls"
	"github.com/stretchr/testify/assert"
	"lcmcontroller/util"
	"testing"
)

func TestValidateIpv4Address_success(t *testing.T) {
	ip := "1.2.3.4"
	err := util.ValidateIpv4Address(ip)
	assert.NoError(t, err, "TestValidateIpv4Address_success execution result")
}

func TestValidateIpv4Address_failure(t *testing.T) {
	ip := ""
	err := util.ValidateIpv4Address(ip)
	assert.Error(t, err, "TestValidateIpv4Address_failure execution result")
}

func TestValidateUUID_success(t *testing.T) {
	uId := "6e5c8bf5-3922-4020-87d3-ee00163ca40d"
	err := util.ValidateUUID(uId)
	assert.NoError(t, err, "TestValidateUUID_success execution result")
}

func TestValidateUUID_invalid(t *testing.T) {
	uId := "sfAdsHuplrmDk44643s"
	err := util.ValidateUUID(uId)
	assert.Error(t, err, "TestValidateUUID_invalid execution result")
}

func TestValidateUUID_failure(t *testing.T) {
	uId := ""
	err := util.ValidateUUID(uId)
	assert.Error(t, err, "TestValidateUUID_failure execution result")
}

func TestValidatePassword_success(t *testing.T) {
	bytes := []byte("Abc@3342")
	err, _ := util.ValidatePassword(&bytes)
	assert.True(t, err, "TestValidatePassword_success execution result")
}

func TestValidatePassword_inavlidlen(t *testing.T) {
	bytes := []byte("aB&32")
	err, _ := util.ValidatePassword(&bytes)
	assert.False(t, err, "TestValidatePassword_invalidlen execution result")
}

func TestValidatePassword_invalid(t *testing.T) {
	bytes := []byte("asdf1234")
	_, _ = util.ValidatePassword(&bytes)
	assert.False(t, false, "TestValidatePassword_invalid execution result")
}

func TestValidateAccessToken_success(t *testing.T) {
	accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGMtODE3OC1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZXhwIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2NEEwMEFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid2Vuc29uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdiNjliIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BUFBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEVOQU5UIl0sImp0aSI6IjQ5ZTBhMGMwLTIxZmItNDAwZC04M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibGVTbXMiOiJ0cnVlIn0.kmJbwyAxPj7OKpP-5r-WMVKbETpKV0kWMguMNaiNt63EhgrmfDgjmX7eqfagMYBS1sgIKZjuxFg2o-HUaO4h9iE1cLkmm0-8qV7HUSkMQThXGtUk2xljB6K9RxxZzzQNQFpgBB7gEcGVc_t_86tLxUU6FxXEW1h-zW4z4I_oGM9TOg7JR-ZyC8lQZTBNiYaOFHpvEubeqfQL0AFIKHeEf18Jm-Xjjw4Y3QEzB1qDMrOGh-55y8kelW1w_Vwbaz45n5-U0DirDpCaa4ergleQIVF6exdjMWKtANGYU6zy48u7EYPYsykkDoIOxWYNqWSe557rNvY_3m1Ynam1QJCYUA"
	err := util.ValidateAccessToken(accessToken)
	assert.Nil(t, err, "TestValidateAccessToken_success execution result")
}

func TestValidateAccessToken_failure(t *testing.T) {
	accessToken := ""
	err := util.ValidateAccessToken(accessToken)
	assert.Error(t, err, "TestValidateAccessToken_failure execution result")
}

func TestValidateAccessToken_invalid(t *testing.T) {
	accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	err := util.ValidateAccessToken(accessToken)
	assert.Error(t, err, "TestValidateAccessToken_invalid execution result")
}

func TestValidateAccessToken_invalid1(t *testing.T) {
	accessToken := "eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGMtODE3OC1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZXhwIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2NEEwMEFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid2Vuc29uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdiNjliIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BUFBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEVOQU5UIl0sImp0aSI6IjQ5ZTBhMGMwLTIxZmItNDAwZC04M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibGVTbXMiOiJ0cnVlIn0."
	err := util.ValidateAccessToken(accessToken)
	assert.Error(t, err, "TestValidateAccessToken_invalid1 execution result")
}

func TestGetDbUser(t *testing.T) {
	err := util.GetDbUser()
	assert.Equal(t, "lcmcontroller", err, "TestGetDbUser execution result")
}

func TestGetDbName(t *testing.T) {
	err := util.GetDbName()
	assert.Equal(t, "lcmcontrollerdb", err, "TestGetDbName execution result")
}

func TestGetDbHost(t *testing.T) {
	err := util.GetDbHost()
	assert.Equal(t, "mepm-postgres", err, "TestGetDbHost execution result")
}

func TestGetDbPort(t *testing.T) {
	err := util.GetDbPort()
	assert.Equal(t, "5432", err, "TestGetDbPort execution result")
}

func TestTLSConfig(t *testing.T) {
	crtName := "crtName"
	_, err := util.TLSConfig(crtName)
	assert.Error(t, err, "TestTLSConfig execution result")
}

func TestValidateFileSize_success(t *testing.T) {
	err := util.ValidateFileSize(10, 100)
	assert.Nil(t, err, "TestValidateFileSize_success execution result")
}

func TestValidateFileSize_invalid(t *testing.T) {
	err := util.ValidateFileSize(100, 10)
	assert.Error(t, err, "TestValidateFileSize_invalid execution result")
}

func TestGetCipherSuites(t *testing.T) {
	sslCiphers := "Dgashsdjh35xgkdgfsdhg"
	err := util.GetCipherSuites(sslCiphers)
	assert.Nil(t, err, "")
}

func TestGetPasswordValidCount(t *testing.T) {
	bytes := []byte("abdsflh")
	err := util.GetPasswordValidCount(&bytes)
	assert.Equal(t, 1, err, "dfdf")
}

func TestGetPasswordValidCount1(t *testing.T) {
	bytes := []byte("GSHDAK")
	err := util.GetPasswordValidCount(&bytes)
	assert.Equal(t, 2, err, "dfdf")
}

func TestGetPasswordValidCount2(t *testing.T) {
	bytes := []byte("3393")
	err := util.GetPasswordValidCount(&bytes)
	assert.Equal(t, 2, err, "dfdf")
}

func TestGetPasswordValidCount3(t *testing.T) {
	bytes := []byte("&$%")
	err := util.GetPasswordValidCount(&bytes)
	assert.Equal(t, 1, err, "dfdf")
}

func TestGetAppConfig(t *testing.T) {
	appConfig := "appConfig"
	util.GetAppConfig(appConfig)
}
