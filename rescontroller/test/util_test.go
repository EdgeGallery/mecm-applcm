package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"rescontroller/util"
	"testing"
)

func TestTLSConfig(t *testing.T) {
	crtName := "crtName"
	_, err := util.TLSConfig(crtName)
	assert.Error(t, err, "TestTLSConfig execution result")
}

func TestGetCipherSuites(t *testing.T) {
	sslCiphers := "Dgashsdjh35xgkdgfsdhg"
	err := util.GetCipherSuites(sslCiphers)
	assert.Nil(t, err, "")
}


func TestGetPasswordValidCount(t *testing.T) {
	bytes := []byte("abdsflh")
	err := util.GetPasswordValidCount(&bytes)
	assert.Equal(t, 1, err, "TestGetPasswordValidCount execution failure")
}

func TestGetPasswordValidCount1(t *testing.T) {
	bytes := []byte("GSHDAK")
	err := util.GetPasswordValidCount(&bytes)
	assert.Equal(t, 2, err, "TestGetPasswordValidCount1 execution failure")
}

func TestGetPasswordValidCount2(t *testing.T) {
	bytes := []byte("3393")
	err := util.GetPasswordValidCount(&bytes)
	assert.Equal(t, 2, err, "TestGetPasswordValidCount2 execution failure")
}

func TestGetPasswordValidCount3(t *testing.T) {
	bytes := []byte("&$%")
	err := util.GetPasswordValidCount(&bytes)
	assert.Equal(t, 1, err, "TestGetPasswordValidCount3 execution failure")
}

func TestGetAppConfig(_ *testing.T) {
	appConfig := "appConfig"
	util.GetAppConfig(appConfig)
}

func TestInvalidPwd(t *testing.T) {
	testVar := "invalidpwd"
	_, err := util.ValidateDbParams(testVar)
	assert.Error(t,  err, "Test invalid password")
}

func TestValidPwd(t *testing.T) {
	testVar := "sa1Znv&srs"
	_, err := util.ValidateDbParams(testVar)
	assert.Nil(t, err, "Test valid password")
}

func TestGetPluginAddress(t *testing.T) {
	addr := util.GetPluginAddress("K8S")
	assert.Equal(t, "", addr, "Test get plugin address")
}

func TestGetPluginPort(t *testing.T) {
	port := util.GetPluginPort("K8S")
	assert.Equal(t, "", port, "Test get plugin port")
}

func TestGetPluginInfo(t *testing.T) {
	pluginInfo := util.GetPluginInfo("")
	assert.Equal(t, "127.0.0.1:10001", pluginInfo, "Test get plugin info")
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

func TestValidateIpv4AddressSuccess(t *testing.T) {
	ip := fmt.Sprintf(ipAddFormatter, rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal),
		rand.Intn(util.MaxIPVal))
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
	_, _ = util.ValidatePassword(&bytes)
	assert.False(t, false, "TestValidatePasswordInvalid execution result")
}

func TestValidateAccessTokenSuccess(t *testing.T) {
	accessToken := createToken("e921ce54-82c8-4532-b5c6-8516cf75f7a6")
	err := util.ValidateAccessToken(accessToken,
		[]string{util.MecmTenantRole, util.MecmAdminRole}, "e921ce54-82c8-4532-b5c6-8516cf75f7a6")
	assert.Nil(t, err, "TestValidateAccessTokenSuccess execution result")
}

func TestValidateAccessTokenFailure(t *testing.T) {
	accessToken := ""
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, util.UserId)
	assert.Nil(t, err, "TestValidateAccessTokenFailure execution result")
}

func TestValidateAccessTokenInvalid(t *testing.T) {
	accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, util.UserId)
	assert.Error(t, err, "TestValidateAccessTokenInvalid execution result")
}

func TestValidateAccessTokenInvalid1(t *testing.T) {
	accessToken := "eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGMtODE3OC1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZ" +
		"XhwIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2NEEwMEFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid" +
		"2Vuc29uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdiNjliIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BU" +
		"FBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEVOQU5UIl0sImp0aSI6IjQ5ZTBhMGMwLTIxZ" +
		"mItNDAwZC04M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibGVTbXMiOiJ0cnVlIn0."
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole}, util.UserId)
	assert.Error(t, err, "TestValidateAccessTokenInvalid1 execution result")
}

func TestValidateSrcAddress(t *testing.T) {
	err := util.ValidateSrcAddress("")
	assert.Error(t, err, "TestValidateSrcAddress execution result")
}

func TestValidateSrcAddress1(t *testing.T) {
	err := util.ValidateSrcAddress("1::1")
	assert.Nil(t, err, "TestValidateSrcAddress execution result")
}

func TestIsRoleAllowed(t *testing.T) {
	err := util.IsRoleAllowed("", []string{})
	assert.False(t, err, "TestIsRoleAllowed execution result")
}
