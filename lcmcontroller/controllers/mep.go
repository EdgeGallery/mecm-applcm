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
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	log.Info("mepm get services request received.")
	url := "https://mep-mm5.mep:80/mep/mec_service_mgmt/v1/services"
	GetFromMep(c, url, clientIp)
}

func (c *MepController) Kong_log() {
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	log.Info("mepm get kong log request received.")
	url := "https://mep-mm5.mep:80/mep/service_govern/v1/kong_log"
	GetFromMep(c, url, clientIp)
}



func GetFromMep(c *MepController, url string, clientIp string){
	rsp, err :=http.Get(url)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.ErrCallFromMep)
		return
	}

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.ErrFromMep)
		return
	}

	_, err = c.Ctx.ResponseWriter.Write(body)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	c.handleLoggingForSuccess(clientIp, "Query from mep successful")
}