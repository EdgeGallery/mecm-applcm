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

// @Title Query Services
// @Description Query Services from Mep Service
// @Param
// @Success 200 ok
// @Failure 400 bad request
// @Failure 500 Mep Service calling failed
// @router /mep/services [get]
func (c *MepController) Services() {
	log.Info("Query services request received.")
	GetFromMep(c,util.MepServiceQuery)
}

// @Title Query Kong Logs
// @Description Query Kong Logs from Mep Service
// @Param
// @Success 200 ok
// @Failure 400 bad request
// @Failure 500 Mep Service calling failed
// @router /mep/kong_log [get]
func (c *MepController) KongLog() {
	log.Info("Query kong log request received.")
	GetFromMep(c,util.MepKongLogQuery)
}

// @Title Query Subscribe
// @Description Query Subscribe from Mep Service
// @Param
// @Success 200 ok
// @Failure 400 bad request
// @Failure 500 Mep Service calling failed
// @router /mep/kong_log [get]
func (c *MepController) Subscribe() {
	log.Info("Query subscribe statistic request received.")
	GetFromMep(c,util.MepSubscribeStatistic)
}

// @Title GetFromMep
// @Description Do get from Mep Service
// @Param c MepController
// @Param url string
// @Success 200 ok
// @Failure 400 bad request
// @Failure 500 Mep Service calling failed
func GetFromMep(c *MepController, url string){
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	//trust all mep ca, for https calling
	config, err := util.TLSConfig("DB_SSL_ROOT_CERT")
	if err != nil {
		log.Error("Unable to send request")
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.ErrCallFromMep)
		return
	}

	tr := &http.Transport{
		TLSClientConfig: config,
	}
	client := &http.Client{Transport: tr}
	response, err := client.Get(url)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.ErrCallFromMep)
		return
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	_, _ = c.Ctx.ResponseWriter.Write(body)
	c.handleLoggingForSuccess(clientIp, "Query data from mep is successful")
}