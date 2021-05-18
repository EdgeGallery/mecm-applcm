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

// Mep controller
package controllers

import (
	"crypto/tls"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"lcmcontroller/util"
	"net/http"
)

// Mep Controller
type MepController struct {
	BaseController
}

func (c *MepController) Services() {
	log.Info("Query mec host request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	url := "https://mep-mm5.mep:80/mep/mec_service_mgmt/v1/services"
	response, err :=client.Get(url)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.ErrCallFromMep)
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	_, _ = c.Ctx.ResponseWriter.Write(body)
	c.handleLoggingForSuccess(clientIp, "Query Service from mep is successful")
}

func (c *MepController) KongLog() {
	log.Info("Query mec host request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	url := "https://mep-mm5.mep:80/mep/service_govern/v1/kong_log"

	response, err := client.Get(url)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.ErrCallFromMep)
		return
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	_, _ = c.Ctx.ResponseWriter.Write(body)
	c.handleLoggingForSuccess(clientIp, "Query Service call status info is successful")
}