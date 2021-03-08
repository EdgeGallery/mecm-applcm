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

// Mec host controller
package controllers

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"lcmcontroller/config"
	"lcmcontroller/models"
	"lcmcontroller/util"
)

// Mec host Controller
type MecHostController struct {
	BaseController
}

// @Title Add MEC host
// @Description Add mec host information
// @Param   body        body    models.MecHostInfo   true      "The mec host information"
// @Param   origin      header  string               true   "origin information"
// @Success 200 ok
// @Failure 400 bad request
// @router /hosts [post, put]
func (c *MecHostController) AddMecHost() {
	log.Info("Add mec host request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	var request models.MecHostInfo
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &request)
	if err != nil {
		c.writeErrorResponse("failed to unmarshal request", util.BadRequest)
		return
	}

	origin := c.Ctx.Request.Header.Get("origin")
	originVar, err := util.ValidateName(origin, util.NameRegex)
	if err != nil || !originVar {
		c.handleLoggingForError(clientIp, util.BadRequest, "Origin is invalid")
		return
	}

	err = c.ValidateAddMecHostRequest(clientIp, request)
	if err != nil {
		return
	}

	err = c.InsertorUpdateMecHostRecord(clientIp, request, origin)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(clientIp, "Add mec host is successful")
	c.ServeJSON()
}

// Validate add mec host request fields
func (c *MecHostController) ValidateAddMecHostRequest(clientIp string, request models.MecHostInfo) error {

	err := util.ValidateIpv4Address(request.MechostIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, "HostIp address is invalid")
		return err
	}

	hostName, err := util.ValidateName(request.MechostName, util.NameRegex)
	if err != nil || !hostName {
		c.handleLoggingForError(clientIp, util.BadRequest, "Mec host name is invalid")
		return err
	}

	zipcode, err := util.ValidateName(request.ZipCode, util.NameRegex)
	if err != nil || !zipcode {
		c.handleLoggingForError(clientIp, util.BadRequest, "Zipcode is invalid")
		return err
	}

	city, err := util.ValidateName(request.City, util.CityRegex)
	if err != nil || !city {
		c.handleLoggingForError(clientIp, util.BadRequest, "City is invalid")
		return err
	}

	if len(request.Address) > 256 {
		c.handleLoggingForError(clientIp, util.BadRequest, "Address is invalid")
		return err
	}

	affinity, err := util.ValidateName(request.Affinity, util.AffinityRegex)
	if err != nil || !affinity {
		c.handleLoggingForError(clientIp, util.BadRequest, "Affinity is invalid")
		return err
	}

	userName, err := util.ValidateName(request.UserName, util.NameRegex)
	if err != nil || !userName {
		c.handleLoggingForError(clientIp, util.BadRequest, "Username is invalid")
		return err
	}

	if len(request.Coordinates) > 128 {
		c.handleLoggingForError(clientIp, util.BadRequest, "Coordinates is invalid")
		return err
	}

	vim, err := util.ValidateName(request.Vim, util.NameRegex)
	if err != nil || !vim {
		c.handleLoggingForError(clientIp, util.BadRequest, "Vim is invalid")
		return err
	}

	return nil
}

func (c *MecHostController) InsertorUpdateMecHostRecord(clientIp string, request models.MecHostInfo, origin string) error {
	// Insert or update host info record
	hostInfoRecord := &models.MecHost{
		MecHostId:   request.MechostIp,
		MechostIp:   request.MechostIp,
		MechostName: request.MechostName,
		ZipCode:     request.ZipCode,
		City:        request.City,
		Address:     request.Address,
		Affinity:    request.Affinity,
		UserName:    request.UserName,
		Coordinates: request.Coordinates,
		Vim:         request.Vim,
		Origin:      origin,
		SyncStatus:  false,
	}

	var mecHostRec models.MecHost
	var recCount = 0
	for _, hwCapRecord := range request.Hwcapabilities {
		capabilityRecord := &models.MecHwCapability{
			MecCapabilityId: hwCapRecord.HwType + request.MechostIp,
			HwType:          hwCapRecord.HwType,
			HwVendor:        hwCapRecord.HwVendor,
			HwModel:         hwCapRecord.HwModel,
			MecHost:         hostInfoRecord,
			Origin:          origin,
			SyncStatus:      false,
		}
		mecHostRec.Hwcapabilities = append(mecHostRec.Hwcapabilities, capabilityRecord)
		recCount++
	}

	count, err := c.Db.QueryCount("mec_host")
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	if count >= util.MaxNumberOfHostRecords {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"Maximum number of host records are exceeded")
		return err
	}

	err = c.Db.InsertOrUpdateData(hostInfoRecord, util.HostIp)
	if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"Failed to save host info record to database.")
		return err
	}

	_, err = c.Db.InsertMulti(recCount, mecHostRec.Hwcapabilities)
	if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError,
			"Failed to save capability info record to database.")
		return err
	}
	return nil
}

// @Title Delete MEC host
// @Description Delete mec host information
// @Param   hostIp   path 	string	true   "hostIp"
// @Success 200 ok
// @Failure 400 bad request
// @router /hosts/:hostIp [post]
func (c *MecHostController) DeleteMecHost() {
	log.Info("Delete mec host request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	hostIp, err := c.getUrlHostIP(clientIp)
	if err != nil {
		return
	}

	err = c.deleteHostInfoRecord(clientIp, hostIp)
	if err != nil {
		return
	}
	c.handleLoggingForSuccess(clientIp, "Delete mec host is successful")
	c.ServeJSON()
}

// Delete host info record
func (c *MecHostController) deleteHostInfoRecord(clientIp, hostIp string) error {

	var appInstances []*models.AppInfoRecord
	_, _ = c.Db.QueryTable("app_info_record").Filter("host_ip", hostIp).All(&appInstances)
	for _, appInstance := range appInstances {
		err := c.TerminateApplication(clientIp, appInstance)
		if err != nil {
			return err
		}
	}

	hostInfoRecord := &models.MecHost{
		MecHostId: hostIp,
	}

	err := c.Db.DeleteData(hostInfoRecord, util.HostIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	return nil
}

// Terminate application
func (c *MecHostController) TerminateApplication(clientIp string, appInstance *models.AppInfoRecord) error {
	appInfoRecord, err := c.getAppInfoRecord(appInstance.AppInsId, clientIp)
	if err != nil {
		return err
	}

	vim, err := c.getVim(clientIp, appInfoRecord.HostIp)
	if err != nil {
		return err
	}

	adapter, err := c.getPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		return err
	}

	_, err = adapter.Terminate(appInfoRecord.HostIp, "", appInfoRecord.AppInsId)
	if err != nil {
		errorString := err.Error()
		c.handleLoggingK8s(clientIp, errorString)
		return err
	}

	acm := config.NewAppConfigMgr(appInfoRecord.AppInsId, "", config.AppAuthConfig{})
	err = acm.DeleteAppAuthConfig()
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	err = c.deleteAppInfoRecord(appInfoRecord.AppInsId)
	if err != nil {
		c.handleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	err = c.deleteTenantRecord(clientIp, appInfoRecord.TenantId)
	if err != nil {
		return err
	}
	return nil
}

// @Title Query MEC hosts
// @Description Query mec host information
// @Success 200 ok
// @Failure 400 bad request
// @router /hosts [get]
func (c *MecHostController) GetMecHost() {
	log.Info("Query mec host request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.handleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	var mecHosts []*models.MecHost
	_, _ = c.Db.QueryTable("mec_host").All(&mecHosts)
	for _, mecHost := range mecHosts {
		_, _ = c.Db.LoadRelated(mecHost, "Hwcapabilities")
	}
	var mecHostsRes []models.MecHostInfo
	res, err := json.Marshal(mecHosts)
	if err != nil {
		c.writeErrorResponse("failed to marshal request", util.BadRequest)
		return
	}
	err = json.Unmarshal(res, &mecHostsRes)
	if err != nil {
		c.writeErrorResponse("failed to unmarshal request", util.BadRequest)
		return
	}
	response, err := json.Marshal(mecHostsRes)
	if err != nil {
		c.writeErrorResponse("failed to marshal request", util.BadRequest)
		return
	}
	_, _ = c.Ctx.ResponseWriter.Write(response)
	c.handleLoggingForSuccess(clientIp, "Query MEC host info is successful")
}