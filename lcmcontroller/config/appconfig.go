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

package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"lcmcontroller/util"
	"net/http"
	"strconv"
)

// Ak sk and appInsId info
type AppAuthConfig struct {
	AppInsId string
	Ak       string
	Sk       string
	AppName  string
}

// App config adapter
type AppConfigAdapter struct {
	AppAuthCfg AppAuthConfig
}

// Credential Info
type Credentials struct {
	AccessKeyId string `json:"accessKeyId"`
	SecretKey   string `json:"secretKey"`
	AppName     string `json:"appName"`
}

// AuthInfo
type AuthInfo struct {
	Credentials Credentials `json:"credentials"`
}

// Auth
type Auth struct {
	AuthInfo AuthInfo `json:"authinfo"`
}

// Constructor to Application configuration
func NewAppConfigMgr(appInsId, appName string, appAuthCfg AppAuthConfig) (acm AppConfigAdapter) {
	acm.AppAuthCfg.AppInsId = appInsId
	acm.AppAuthCfg.AppName = appName
	if (appAuthCfg != AppAuthConfig{}) {
		acm.AppAuthCfg.Ak = appAuthCfg.Ak
		acm.AppAuthCfg.Sk = appAuthCfg.Sk
	}
	return
}

// Constructor to Application configuration
func NewAppAuthCfg(appInsId string) (appAuthCfg AppAuthConfig) {
	appAuthCfg.AppInsId = appInsId
	return
}

// Generate ak sk values
func (appAuthCfg *AppAuthConfig) GenerateAkSK() error {
	akBuff := make([]byte, 14)
	_, err := rand.Read(akBuff)
	if err != nil {
		return err
	}
	ak := base64.StdEncoding.EncodeToString(akBuff)

	skBuff := make([]byte, 48)
	_, err = rand.Read(skBuff)
	if err != nil {
		return err
	}
	sk := base64.StdEncoding.EncodeToString(skBuff)
	appAuthCfg.Ak = ak
	appAuthCfg.Sk = sk
	return nil
}

// Send app auth configuration request
func (acm *AppConfigAdapter) PostAppAuthConfig() error {
	authInfo := Auth{
		AuthInfo{
			Credentials{
				AccessKeyId: acm.AppAuthCfg.Ak,
				SecretKey:   acm.AppAuthCfg.Sk,
				AppName:     acm.AppAuthCfg.AppName,
			},
		},
	}

	requestBody, err := json.Marshal(authInfo)
	if err != nil {
		log.Error("Failed to marshal the request body information")
		return err
	}
	url := util.HttpsUrl + util.GetAPIGwAddr() + ":" + util.GetAPIGwPort() + "/mepauth/v1/applications/" +
		acm.AppAuthCfg.AppInsId + "/confs"
	req, errNewRequest := http.NewRequest("PUT", url, bytes.NewBuffer(requestBody))
	if errNewRequest != nil {
		return errNewRequest
	}
	response, errDo := util.DoRequest(req)
	if errDo != nil {
		log.Error("Failed to send the request to mep", errDo)
		return errDo
	}
	defer response.Body.Close()
	_, err2 := ioutil.ReadAll(response.Body)
	if err2 != nil {
		return err2
	}
	log.Info("response is received")

	if response.StatusCode != http.StatusOK {
		return errors.New("created failed, status is " + strconv.Itoa(response.StatusCode))
	}

	return nil
}

// Delete app auth configuration request
func (acm *AppConfigAdapter) DeleteAppAuthConfig() error {
	url := util.HttpsUrl + util.GetAPIGwAddr() + ":" + util.GetAPIGwPort() + "/mepauth/v1/applications/" +
		acm.AppAuthCfg.AppInsId + "/confs"
	req, errNewRequest := http.NewRequest("DELETE", url, nil)
	if errNewRequest != nil {
		return errNewRequest
	}
	response, errDo := util.DoRequest(req)
	if errDo != nil {
		return errDo
	}
	defer response.Body.Close()
	_, err2 := ioutil.ReadAll(response.Body)
	if err2 != nil {
		return err2
	}
	log.Info("response is received")

	if response.StatusCode != http.StatusOK {
		return errors.New("created failed, status is " + strconv.Itoa(response.StatusCode))
	}

	return nil
}
