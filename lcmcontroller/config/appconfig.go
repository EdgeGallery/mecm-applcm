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
}

// App config adapter
type AppConfigAdapter struct {
	AppAuthCfg AppAuthConfig
}

// Constructor to Application configuration
func NewAppConfigMgr(appInsId string, appAuthCfg AppAuthConfig) (acm AppConfigAdapter) {
	acm.AppAuthCfg.AppInsId = appInsId
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

	skBuff := make([]byte, 28)
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
	requestBody, err := json.Marshal(map[string]string{"appInsId": acm.AppAuthCfg.AppInsId, "ak": acm.AppAuthCfg.Ak, "sk": acm.AppAuthCfg.Sk})
	if err != nil {
		log.Error("Failed to marshal the request body information")
		return err
	}
	url := util.HttpsUrl + util.GetAPIGwAddr() + ":" + util.GetAPIGwPort() + "/mepauth/v1/appconfig"
	req, errNewRequest := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
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

	if response.StatusCode != http.StatusCreated {
		return errors.New("created failed, status is " + strconv.Itoa(response.StatusCode))
	}

	return nil
}

