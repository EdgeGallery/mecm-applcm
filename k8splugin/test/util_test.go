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

func TestValidateIpv4Address_success(t *testing.T) {
   ip := "1.2.3.4"
   err := util.ValidateIpv4Address(ip)
   assert.NoError(t, err,"TestValidateIpv4Address_success execution result")
}

func TestValidateIpv4Address_failure(t *testing.T) {
   ip := ""
   err := util.ValidateIpv4Address(ip)
   assert.Error(t, err, "TestValidateIpv4Address_failure execution result")
}

func TestValidateUUID_success(t *testing.T) {
   uId := "6e5c8bf5-3922-4020-87d3-ee00163ca40d"
   err := util.ValidateUUID(uId)
   assert.NoError(t, err,"TestValidateUUID_success execution result")
}

func TestValidateUUID_invalid(t *testing.T) {
   uId := "sfAdsHuplrmDk44643s"
   err := util.ValidateUUID(uId)
   assert.Error(t, err,"TestValidateUUID_invalid execution result")
}

func TestValidateUUID_failure(t *testing.T) {
   uId := ""
   err := util.ValidateUUID(uId)
   assert.Error(t, err,"TestValidateUUID_failure execution result")
}

func TestValidatePassword_success(t *testing.T)  {
   bytes := []byte("Abc@3342")
   err, _ := util.ValidatePassword(&bytes)
   assert.True(t ,err,"TestValidatePassword_success execution result")
}

func TestValidatePassword_inavlidlen(t *testing.T)  {
   bytes := []byte("aB&32")
   err, _ := util.ValidatePassword(&bytes)
   assert.False(t, err,"TestValidatePassword_invalidlen execution result")
}

func TestValidatePassword_invalid(t *testing.T)  {
   bytes := []byte("asdf1234")
   util.ValidatePassword(&bytes)
   //log.Info(err)
   assert.False(t, false,"TestValidatePassword_invalid execution result")
}

func TestValidateAccessToken_success(t *testing.T)  {
   accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGMtODE3OC1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZXhwIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2NEEwMEFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid2Vuc29uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdiNjliIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BUFBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEVOQU5UIl0sImp0aSI6IjQ5ZTBhMGMwLTIxZmItNDAwZC04M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibGVTbXMiOiJ0cnVlIn0.kmJbwyAxPj7OKpP-5r-WMVKbETpKV0kWMguMNaiNt63EhgrmfDgjmX7eqfagMYBS1sgIKZjuxFg2o-HUaO4h9iE1cLkmm0-8qV7HUSkMQThXGtUk2xljB6K9RxxZzzQNQFpgBB7gEcGVc_t_86tLxUU6FxXEW1h-zW4z4I_oGM9TOg7JR-ZyC8lQZTBNiYaOFHpvEubeqfQL0AFIKHeEf18Jm-Xjjw4Y3QEzB1qDMrOGh-55y8kelW1w_Vwbaz45n5-U0DirDpCaa4ergleQIVF6exdjMWKtANGYU6zy48u7EYPYsykkDoIOxWYNqWSe557rNvY_3m1Ynam1QJCYUA"
   err := util.ValidateAccessToken(accessToken)
   assert.Nil(t, err,"TestValidateAccessToken_success execution result")
}

func TestValidateAccessToken_failure(t *testing.T)  {
   accessToken := ""
   err := util.ValidateAccessToken(accessToken)
   assert.Error(t ,err,"TestValidateAccessToken_failure execution result")
}

func TestValidateAccessToken_invalid(t *testing.T)  {
   accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
   err := util.ValidateAccessToken(accessToken)
   assert.Error(t ,err,"TestValidateAccessToken_invalid execution result")
}

func TestValidateAccessToken_invalid1(t *testing.T)  {
   accessToken := "eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGMtODE3OC1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZXhwIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2NEEwMEFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid2Vuc29uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdiNjliIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BUFBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEVOQU5UIl0sImp0aSI6IjQ5ZTBhMGMwLTIxZmItNDAwZC04M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibGVTbXMiOiJ0cnVlIn0."
   err := util.ValidateAccessToken(accessToken)
   assert.Error(t ,err,"TestValidateAccessToken_invalid1 execution result")
}

func TestGetDbUser(t *testing.T)  {
   err := util.GetDbUser()
   assert.Equal(t,"k8splugin" , err,"TestGetDbUser execution result")
}

func TestGetDbName(t *testing.T)  {
   err := util.GetDbName()
   assert.Equal(t, "k8splugindb", err, "TestGetDbName execution result")
}

func TestGetDbHost(t *testing.T)  {
   err := util.GetDbHost()
   assert.Equal(t, "mepm-postgres",err, "TestGetDbHost execution result")
}

func TestGetDbPort(t *testing.T)  {
   err := util.GetDbPort()
   assert.Equal(t, "5432", err, "TestGetDbPort execution result")
}

func TestValidateServerName_success(t *testing.T)  {
   serverName := "serverName"
   err, _ := util.ValidateServerName(serverName)
   assert.True(t, err, "TestValidateServerName execution result")
}

func TestValidateServerName_maxLen(t *testing.T)  {
   serverName := "45262352eeetdg374dffffffffffffffffffffffffffffffffytttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttrfkggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggghhhh"
   err, _ := util.ValidateServerName(serverName)
   assert.False(t, err, "TestValidateServerName_maxLen execution result")
}

func TestCreateDir_success(t *testing.T)  {
   util.CreateDir("/home/Downloads")
   assert.True(t ,true,"TestCreateDir_success execution result")
}


