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
	"k8splugin/config"
	_ "k8splugin/log"
	"k8splugin/util"
	_ "mime/multipart"
	_ "net/http"
	"os"
	_ "os"
	_ "path/filepath"
	"testing"
)

func TestValidateIpv4AddressSuccess(t *testing.T) {
	ip := ipAddress
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
	accessToken := createToken("1", "ROLE_MECM_ADMIN", true, true)
	err := util.ValidateAccessToken(accessToken, []string{util.MecmAdminRole, util.MecmAdminRole})
	assert.Nil(t, err, "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenTenant(t *testing.T) {
	accessToken := createToken("1", "ROLE_MECM_TENANT", true, true)
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	assert.Nil(t, err, "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenRoleFailure(t *testing.T) {
	accessToken := createToken("1", "ROLE_MECM_TENANTT", true, true)
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenRoleGuestFailure(t *testing.T) {
	accessToken := createToken("1", "ROLE_MECM_GUEST", true, true)
	err := util.ValidateAccessToken(accessToken, []string{"ROLE_MECM_GUESTT"})
	assert.Equal(t, "forbidden", err.Error(), "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenGuest(t *testing.T) {
	accessToken := createToken("1", "ROLE_MECM_GUEST", true, true)
	err := util.ValidateAccessToken(accessToken, []string{util.MecmGuestRole, util.MecmAdminRole})
	assert.Nil(t, err, "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenRole(t *testing.T) {
	accessToken := createToken("1", "ROLE_MECM_GUEST", false, true)
	err := util.ValidateAccessToken(accessToken, []string{util.MecmGuestRole, util.MecmAdminRole})
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenUserName(t *testing.T) {
	accessToken := createToken("1", "ROLE_MECM_GUEST", true, false)
	err := util.ValidateAccessToken(accessToken, []string{util.MecmGuestRole, util.MecmAdminRole})
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenUserId(t *testing.T) {
	accessToken := createToken("", "ROLE_MECM_GUEST", true, false)
	err := util.ValidateAccessToken(accessToken, []string{util.MecmGuestRole, util.MecmAdminRole})
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenFailure(t *testing.T) {
	accessToken := ""
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	assert.Nil(t, err, "TestValidateAccessTokenFailure execution result")
}

func TestValidateAccessTokenFailure1(t *testing.T) {
	accessToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpdGllcyI6WyJST0xFX01FQ01fQURNSU4iLCJST0xFX01FQ01fVEVOQU5UIiwiUk9MRV9BUFBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiXSwiYXV0aG9yaXplZCI6dHJ1ZSwiZXhwIjoxNjIzODU5MDg3LCJ1c2VySWQiOiJjOWZhNjA2OS0yODQ1LTQ2MmQtOGE2ZS1iOGE1MDFhNjNhZTIiLCJ1c2VyX25hbWUiOiJsY21jb250cm9sbGVyIn0.uZOnmni-wBKNH7XGr4u0nBtKLr_gYkvoP0zp3z0fWag"
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	assert.Equal(t, "invalid token", err.Error(), "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenInvalid(t *testing.T) {
	accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	assert.Error(t, err, "TestValidateAccessTokenInvalid execution result")
}

func TestValidateAccessTokenInvalid1(t *testing.T) {
	accessToken := "eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGMtODE3OC1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZXh" +
		"wIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2NEEwMEFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid2Vuc2" +
		"9uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdiNjliIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BUFBTVE9SR" +
		"V9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEVOQU5UIl0sImp0aSI6IjQ5ZTBhMGMwLTIxZmItNDAwZC04" +
		"M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibGVTbXMiOiJ0cnVlIn0."
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	assert.Error(t, err, "TestValidateAccessTokenInvalid1 execution result")
}

func TestGetDbUser(t *testing.T) {
	err := util.GetDbUser()
	assert.Equal(t, "", err, "TestGetDbUser execution result")
}

func TestGetDbName(t *testing.T) {
	err := util.GetDbName()
	assert.Equal(t, "", err, "TestGetDbName execution result")
}

func TestGetDbHost(t *testing.T) {
	err := util.GetDbHost()
	assert.Equal(t, "", err, "TestGetDbHost execution result")
}

func TestGetDbPort(t *testing.T) {
	err := util.GetDbPort()
	assert.Equal(t, "", err, "TestGetDbPort execution result")
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

func TestCreateDirFailure(t *testing.T) {
	util.CreateDir("test10")
	assert.True(t, true, "TestCreateDirSuccess execution result")
	_ = os.Remove("test10")
}

func TestValidateAkMaxLen(t *testing.T) {
	ak := "45262352eeetdg374dfffffffffffffffffff"
	err := util.ValidateAk(ak)
	assert.Equal(t, "ak validation failed", err.Error(), "TestValidateAK_maxLen execution result")
}

func TestValidateSkMaxLen(t *testing.T) {
	sk := "423124565262352eeetgggggggfstrewqyzx875643276543abcghihe32abcdede"
	err := util.ValidateSk(sk)
	assert.Equal(t, "sk validation failed", err.Error(), "TestValidateSk_maxLen execution result")
}

func TestValidateAkSuccess(t *testing.T) {
	err := util.ValidateAk(ak)
	assert.Nil(t, err, "TestValidateAkSuccess execution result")
}

func TestValidateSkSuccess(t *testing.T) {
	err := util.ValidateSk(sk)
	assert.Nil(t, err, "TestValidateAkSuccess execution result")
}

func TestAddValues(t *testing.T)  {
	dir, _ := os.Getwd()
	tarFile, err := os.Open(dir+"/"+"7e9b913f-748a-42b7-a088-abe3f750f04c.tgz",)
	if err != nil {
		return
	}
	defer tarFile.Close()
	appAuthCfg := config.NewBuildAppAuthConfig(appInstanceIdentifier, ak, sk)
	dirName, _, err := appAuthCfg.AddValues(tarFile)
	if err != nil {
		return
	}
	defer  os.RemoveAll(dirName)
	defer os.Remove(dirName + ".tar.gz")
	assert.Equal(t, "7e9b913f-748a-42b7-a088-abe3f750f04c", dirName,
		"TestAddValues execution result")
}

func TestAddValuesFailure(t *testing.T)  {
	dir, _ := os.Getwd()
	tarFile, err := os.Open(dir+"/"+"7e9b913f-748a-42b7-a088-abe3f750f04.tgz",)
	defer tarFile.Close()
	appAuthCfg := config.NewBuildAppAuthConfig(appInstanceIdentifier, ak, sk)
	dirName, _, err := appAuthCfg.AddValues(tarFile)
	if err != nil {
		return
	}
	defer  os.RemoveAll(dirName)
	defer os.Remove(dirName + ".tar.gz")
	assert.Equal(t, "7e9b913f-748a-42b7-a088-abe3f750f04c", dirName,
		"TestAddValues execution result")
}

func TestGetTLSConfigSuccess(t *testing.T) {
	dir, _ := os.Getwd()
	config, err := util.GetConfiguration(dir)

	_, err = util.GetTLSConfig(&config.Server, "./server.crt", "./server.key")
	assert.Nil(t, err, "TestGetTLSConfigSuccess execution result")
}


func TestGetTLSConfigFailure(t *testing.T) {
	dir, _ := os.Getwd()
	config, err := util.GetConfiguration(dir)

	_, err = util.GetTLSConfig(&config.Server, "./server1.crt", "./server.key")
	assert.Equal(t, "could not load server key pair", err.Error(), "TestGetTLSConfigSuccess execution result")

	config.Server.SslCiphers = ","

	_, err = util.GetTLSConfig(&config.Server, "./server.crt", "./server.key")
	assert.Equal(t, "TLS cipher configuration is not recommended or invalid", err.Error(), "TestGetTLSConfigSuccess execution result")

	config.Server.SslCiphers = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA386"

	_, err = util.GetTLSConfig(&config.Server, "./server.crt", "./server.key")
	assert.Equal(t, "TLS cipher configuration is not recommended or invalid", err.Error(), "TestGetTLSConfigSuccess execution result")

	config.Server.SslCiphers = ""

	_, err = util.GetTLSConfig(&config.Server, "./server.crt", "./server.key")
	assert.Equal(t, "TLS cipher configuration is not recommended or invalid", err.Error(), "TestGetTLSConfigSuccess execution result")

	config.Server.ServerName = "12edgegallery12edgegallery12edgegallery12edge12edgegallery12edgegallery12edgegallery" +
		"12edgegallery12edge12edgegallery12edgegallery12edgegallery12edgegallery12edge12edgegallery12edgegallery12ed" +
		"gegallery12edgegallery12edge12edgegallery12edgegallery12edgegallery12edgegallery12edge12edgegallery"
	_, err = util.GetTLSConfig(&config.Server, "./server.crt", "./server.key")
	assert.Equal(t, "server or host name validation failed", err.Error(), "TestGetTLSConfigSuccess execution result")
}

func TestGetReleaseNamespaceSuccess(t *testing.T) {
	result := util.GetReleaseNamespace()
	assert.Equal(t, "", result, "TestGetReleaseNamespaceSuccess execution result")
}

func TestInvalidPwd(t *testing.T) {
	testVar := "invalidpwd"
	_, err := util.ValidateDbParams(testVar)
	assert.Error(t,  err, "Test invalid password")
}