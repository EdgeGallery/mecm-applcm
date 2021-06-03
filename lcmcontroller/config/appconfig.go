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

type ApplicationConfig struct {
	ToscaDefinitionsVersion string   `json:"tosca_definitions_version"`
	Description             string   `json:"description"`
	Imports                 []string `json:"imports"`
	Metadata                struct {
		TemplateName    string `json:"template_name"`
		TemplateAuthor  string `json:"template_author"`
		TemplateVersion string `json:"template_version"`
		VnfmType        string `json:"vnfm_type"`
		VnfdID          string `json:"vnfd_id"`
		VnfdVersion     string `json:"vnfd_version"`
		VnfdName        string `json:"vnfd_name"`
		VnfdDescription string `json:"vnfd_description"`
	} `json:"metadata"`
	TopologyTemplate struct {
		NodeTemplates struct {
			AppConfiguration struct {
				Type       string `json:"type"`
				Properties struct {
					Appservicerequired []struct {
						Sername              string `json:"serName"`
						Version              string    `json:"version"`
						Requestedpermissions bool   `json:"requestedPermissions"`
					} `json:"appServiceRequired"`
					Appserviceoptional []struct {
						Sername              string `json:"serName"`
						Version              string    `json:"version"`
						Requestedpermissions bool   `json:"requestedPermissions"`
					} `json:"appServiceOptional"`
					Appserviceproduced []struct {
						Sername           string   `json:"serName"`
						Version           string      `json:"version"`
						Dnsruleidlist     []string `json:"dnsRuleIdList"`
						Trafficruleidlist []string `json:"trafficRuleIdList"`
					} `json:"appServiceProduced"`
					Appfeaturerequired []struct {
						Featurename string `json:"featureName"`
						Version     string    `json:"version"`
					} `json:"appFeatureRequired"`
					Appfeatureoptional []struct {
						Featurename string `json:"featureName"`
						Version     string    `json:"version"`
					} `json:"appFeatureOptional"`
					Appname string `json:"appName"`
				} `json:"properties"`
			} `json:"app_configuration"`
		} `json:"node_templates"`
	} `json:"topology_template"`
}
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
	AppInfo    AppInfo
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
	AuthInfo AuthInfo `json:"authInfo"`
	AppAuthInfo AppInfo `json:"appInfo"`
}

// App Auth info
type AppInfo struct {
	AppName             string   `json:"appName"`
	RequiredServices    []string `json:"requiredServices"`
}

// Constructor to Application configuration
func NewAppConfigMgr(appInsId, appName string, appAuthCfg AppAuthConfig, appConfig ApplicationConfig) (acm AppConfigAdapter) {
	acm.AppAuthCfg.AppInsId = appInsId
	acm.AppAuthCfg.AppName = appName
	if (appAuthCfg != AppAuthConfig{}) {
		acm.AppAuthCfg.Ak = appAuthCfg.Ak
		acm.AppAuthCfg.Sk = appAuthCfg.Sk

		acm.AppInfo.AppName = appConfig.TopologyTemplate.NodeTemplates.AppConfiguration.Properties.Appname
		for _, appServiceOptional := range appConfig.TopologyTemplate.NodeTemplates.AppConfiguration.Properties.Appserviceoptional {
			acm.AppInfo.RequiredServices = append(acm.AppInfo.RequiredServices, appServiceOptional.Sername)
		}
		for _, appServiceProduced := range appConfig.TopologyTemplate.NodeTemplates.AppConfiguration.Properties.Appserviceproduced {
			acm.AppInfo.RequiredServices = append(acm.AppInfo.RequiredServices, appServiceProduced.Sername)
		}
		for _, appServiceRequired := range appConfig.TopologyTemplate.NodeTemplates.AppConfiguration.Properties.Appservicerequired {
			acm.AppInfo.RequiredServices = append(acm.AppInfo.RequiredServices, appServiceRequired.Sername)
		}
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
func (acm *AppConfigAdapter) PostAppAuthConfig(clientIp string) error {
	authInfo := Auth{
		AuthInfo{
			Credentials{
				AccessKeyId: acm.AppAuthCfg.Ak,
				SecretKey:   acm.AppAuthCfg.Sk,
				AppName:     acm.AppAuthCfg.AppName,
			},
		},
		AppInfo{
			AppName: acm.AppInfo.AppName,
			RequiredServices: acm.AppInfo.RequiredServices,
		},
	}

	requestBody, err := json.Marshal(authInfo)
	if err != nil {
		log.Error("Failed to marshal the request body information")
		return err
	}
	url := util.HttpsUrl + util.GetAPIGwAddr() + ":" + util.GetAPIGwPort() + "/mep/appMng/v1/applications/" +
		acm.AppAuthCfg.AppInsId + "/confs"
	req, errNewRequest := http.NewRequest("PUT", url, bytes.NewBuffer(requestBody))
	if errNewRequest != nil {
		return errNewRequest
	}
	req.Header.Set("X-Real-Ip", clientIp)
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
func (acm *AppConfigAdapter) DeleteAppAuthConfig(clientIp string) error {

	url := util.HttpsUrl + util.GetMepServerAddress() + ":" + util.GetMepPort() + "/mep/mec_app_support/v1/applications/" +
		acm.AppAuthCfg.AppInsId + "/AppInstanceTermination"
	req, errNewRequest := http.NewRequest("DELETE", url, nil)
	if errNewRequest != nil {
		return errNewRequest
	}
	req.Header.Set("X-AppinstanceID", acm.AppAuthCfg.AppInsId)
	req.Header.Set("X-Real-Ip", clientIp)
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
