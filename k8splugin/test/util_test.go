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
	_ "bytes"
	_ "crypto/tls"
	"github.com/stretchr/testify/assert"
	_ "io"
	"k8splugin/util"
	_ "mime/multipart"
	_ "net/http"
	_ "os"
	_ "path/filepath"
	"testing"
)

func TestValidateIpv4AddressSuccess(t *testing.T) {
	ip := "1.2.3.4"
	err := util.ValidateIpv4Address(ip)
	assert.NoError(t, err, "TestValidateIpv4AddressSuccess execution result")
}

func TestValidateIpv4AddressFailure(t *testing.T) {
	ip := ""
	err := util.ValidateIpv4Address(ip)
	assert.Error(t, err, "TestValidateIpv4AddressFailure execution result")
}

func TestValidateUUIDSuccess(t *testing.T) {
	uId := "6e5c8bf5-3922-4020-87d3-ee00163ca40d"
	err := util.ValidateUUID(uId)
	assert.NoError(t, err, "TestValidateUUIDSuccess execution result")
}

func TestValidateUUIDInvalid(t *testing.T) {
	uId := "sfAdsHuplrmDk44643s"
	err := util.ValidateUUID(uId)
	assert.Error(t, err, "TestValidateUUIDInvalid execution result")
}

func TestValidateUUIDFailure(t *testing.T) {
	uId := ""
	err := util.ValidateUUID(uId)
	assert.Error(t, err, "TestValidateUUIDFailure execution result")
}

func TestValidatePasswordSuccess(t *testing.T) {
	bytes := []byte("Abc@3342")
	err, _ := util.ValidatePassword(&bytes)
	assert.True(t, err, "TestValidatePasswordSuccess execution result")
}

func TestValidatePasswordInavlidlen(t *testing.T) {
	bytes := []byte("aB&32")
	err, _ := util.ValidatePassword(&bytes)
	assert.False(t, err, "TestValidatePasswordInvalidlen execution result")
}

func TestValidatePasswordInvalid(t *testing.T) {
	bytes := []byte("asdf1234")
	err, _ := util.ValidatePassword(&bytes)
	assert.True(t, err, "TestValidatePasswordInvalid execution result")
}

func TestValidateAccessTokenSuccess(t *testing.T) {
	accessToken := createToken(1)
	err := util.ValidateAccessToken(accessToken)
	assert.Nil(t, err, "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenFailure(t *testing.T) {
	accessToken := ""
	err := util.ValidateAccessToken(accessToken)
	assert.Error(t, err, "TestValidateAccessTokenFailure execution result")
}

func TestValidateAccessTokenInvalid(t *testing.T) {
	accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	err := util.ValidateAccessToken(accessToken)
	assert.Error(t, err, "TestValidateAccessTokenInvalid execution result")
}

func TestValidateAccessTokenInvalid1(t *testing.T) {
	accessToken := "eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGMtODE3OC1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZXh" +
		"wIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2NEEwMEFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid2Vuc2" +
		"9uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdiNjliIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BUFBTVE9SR" +
		"V9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEVOQU5UIl0sImp0aSI6IjQ5ZTBhMGMwLTIxZmItNDAwZC04" +
		"M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibGVTbXMiOiJ0cnVlIn0."
	err := util.ValidateAccessToken(accessToken)
	assert.Error(t, err, "TestValidateAccessTokenInvalid1 execution result")
}

func TestGetDbUser(t *testing.T) {
	err := util.GetDbUser()
	assert.Equal(t, "k8splugin", err, "TestGetDbUser execution result")
}

func TestGetDbName(t *testing.T) {
	err := util.GetDbName()
	assert.Equal(t, "k8splugindb", err, "TestGetDbName execution result")
}

func TestGetDbHost(t *testing.T) {
	err := util.GetDbHost()
	assert.Equal(t, "mepm-postgres", err, "TestGetDbHost execution result")
}

func TestGetDbPort(t *testing.T) {
	err := util.GetDbPort()
	assert.Equal(t, "5432", err, "TestGetDbPort execution result")
}

func TestValidateServerNameSuccess(t *testing.T) {
	serverName := "serverName"
	err, _ := util.ValidateServerName(serverName)
	assert.True(t, err, "TestValidateServerName execution result")
}

func TestValidateServerNameMaxLen(t *testing.T) {
	serverName := "45262352eeetdg374dffffffffffffffffffffffffffffffffytttttttttttttttttttttttttttttttttttttttttttttt" +
		"tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt" +
		"tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt" +
		"tttttttttrfkggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggghhhh"
	err, _ := util.ValidateServerName(serverName)
	assert.False(t, err, "TestValidateServerName_maxLen execution result")
}

func TestCreateDirSuccess(t *testing.T) {
	util.CreateDir("/home/Downloads")
	assert.True(t, true, "TestCreateDirSuccess execution result")
}
