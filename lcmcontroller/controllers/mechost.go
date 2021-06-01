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
	"strings"
)

// Mec host Controller
type MecHostController struct {
	BaseController
}

// @Title Add MEC host
// @Description Add mec host information
// @Param   body        body    models.MecHostInfo   true      "The mec host information"
// @Success 200 ok
// @Failure 400 bad request
// @router /hosts [post]
func (c *MecHostController) AddMecHost() {
	log.Info("Add or update mec host request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	var request models.MecHostInfo
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &request)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}

	err = c.ValidateAddMecHostRequest(clientIp, request)
	if err != nil {
		c.writeErrorResponse("failed to add mec host request", util.BadRequest)
		return
	}

	err = c.InsertorUpdateMecHostRecord(clientIp, request)
	if err != nil {
		c.writeErrorResponse("failed to insert or update mec host record", util.BadRequest)
		return
	}

	c.handleLoggingForSuccess(clientIp, "Add or update mec host is successful")
	c.ServeJSON()
}

// @Title Update MEC host
// @Description Add mec host information
// @Param   body        body    models.MecHostInfo   true      "The mec host information"
// @Success 200 ok
// @Failure 400 bad request
// @router /hosts [put]
func (c *MecHostController) UpdateMecHost() {
	log.Info("Add or Update mec host request received.")
	c.AddMecHost()
}

// Validate add mec host request fields
func (c *MecHostController) ValidateAddMecHostRequest(clientIp string, request models.MecHostInfo) error {

	err := util.ValidateIpv4Address(request.MechostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "MecHost address is invalid")
		return err
	}

	err = c.validateMecHostZipCodeCity(request, clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Clientip is invalid")
		return err
	}

	if len(request.Address) > 256 {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Address is invalid")
		return err
	}

	affinity, err := util.ValidateName(request.Affinity, util.AffinityRegex)
	if err != nil || !affinity {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Affinity is invalid")
		return err
	}

	userName, err := util.ValidateName(request.UserName, util.NameRegex)
	if err != nil || !userName {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Username is invalid")
		return err
	}

	if len(request.Coordinates) > 128 {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Coordinates is invalid")
		return err
	}

	vim, err := util.ValidateName(request.Vim, util.NameRegex)
	if err != nil || !vim {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Vim is invalid")
		return err
	}

	originVar, err := util.ValidateName(request.Origin, util.NameRegex)
	if err != nil || !originVar {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Origin is invalid")
		return err
	}

	return nil
}

// Insert or update mec host record
func (c *MecHostController) InsertorUpdateMecHostRecord(clientIp string, request models.MecHostInfo) error {

	if request.Origin == "" {
		request.Origin = "MEO"
	}

	syncStatus := true
	if request.Origin == "MEPM" {
		syncStatus = false
	}
	// Insert or update host info record
	hostInfoRecord := &models.MecHost{
		MecHostId:          request.MechostIp,
		MechostIp:          request.MechostIp,
		MechostName:        request.MechostName,
		ZipCode:            request.ZipCode,
		City:               request.City,
		Address:            request.Address,
		Affinity:           request.Affinity,
		UserName:           request.UserName,
		ConfigUploadStatus: "",
		Coordinates:        request.Coordinates,
		Vim:                request.Vim,
		Origin:             request.Origin,
		SyncStatus:         syncStatus,
	}

	count, err := c.Db.QueryCount(util.Mec_Host)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	if count >= util.MaxNumberOfHostRecords {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError,
			"Maximum number of host records are exceeded")
		return err
	}

	err = c.Db.InsertOrUpdateData(hostInfoRecord, util.HostIp)
	if err != nil && err.Error() != util.LastInsertIdNotSupported {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError,
			"Failed to save host info record to database.")
		return err
	}

	for _, hwCapRecord := range request.Hwcapabilities {
		capabilityRecord := &models.MecHwCapability{
			MecCapabilityId: hwCapRecord.HwType + request.MechostIp,
			HwType:          hwCapRecord.HwType,
			HwVendor:        hwCapRecord.HwVendor,
			HwModel:         hwCapRecord.HwModel,
			MecHost:         hostInfoRecord,
		}
		err = c.Db.InsertOrUpdateData(capabilityRecord, "mec_capability_id")
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleLoggingForError(clientIp, util.StatusInternalServerError,
				"Failed to save capability info record to database.")
			return err
		}
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
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	hostIp, err := c.getUrlHostIP(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}

	err = c.deleteHostInfoRecord(clientIp, hostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.handleLoggingForSuccess(clientIp, "Delete mec host is successful")
	c.ServeJSON()
}

// Delete host info record
func (c *MecHostController) deleteHostInfoRecord(clientIp, hostIp string) error {

	var appInstances []*models.AppInfoRecord
	_, _ = c.Db.QueryTable("app_info_record", &appInstances, "mec_host", hostIp)
	for _, appInstance := range appInstances {
		err := c.TerminateApplication(clientIp, appInstance.AppInstanceId)
		if err != nil {
			return err
		}
	}

	hostInfoRecord := &models.MecHost{
		MecHostId: hostIp,
	}

	readErr := c.Db.ReadData(hostInfoRecord, util.HostIp)
	if readErr != nil {
		c.HandleLoggingForError(clientIp, util.StatusNotFound,
			"Mec host info record does not exist in database")
		return readErr
	}
	var origin = hostInfoRecord.Origin

	err := c.Db.DeleteData(hostInfoRecord, util.HostIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	mecHostKeyRec := &models.MecHostStaleRec{
		MecHostId: hostIp,
	}

	if strings.EqualFold(origin, "mepm") {
		err = c.Db.InsertOrUpdateData(mecHostKeyRec, util.HostIp)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
			return err
		}
	}

	return nil
}

// Terminate application
func (c *MecHostController) TerminateApplication(clientIp string, appInsId string) error {
	appInfoRecord, err := c.getAppInfoRecord(appInsId, clientIp)
	if err != nil {
		return err
	}

	vim, err := c.getVim(clientIp, appInfoRecord.MecHost)
	if err != nil {
		return err
	}

	adapter, err := c.getPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		return err
	}

	_, err = adapter.Terminate(appInfoRecord.MecHost, "", appInfoRecord.AppInstanceId)
	if err != nil {
		c.HandleLoggingForFailure(clientIp, err.Error())
		return err
	}

	acm := config.NewAppConfigMgr(appInfoRecord.AppInstanceId, "", config.AppAuthConfig{})
	err = acm.DeleteAppAuthConfig(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	var origin = appInfoRecord.Origin
	var tenantId = appInfoRecord.TenantId
	err = c.deleteAppInfoRecord(appInfoRecord.AppInstanceId)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
		return err
	}

	err = c.deleteTenantRecord(clientIp, appInfoRecord.TenantId)
	if err != nil {
		return err
	}

	appInsKeyRec := &models.AppInstanceStaleRec{
		AppInstanceId: appInsId,
		TenantId:      tenantId,
	}

	if strings.EqualFold(origin, "mepm") {
		err = c.Db.InsertOrUpdateData(appInsKeyRec, util.AppInsId)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			log.Error("Failed to save app instance key record to database.")
			return err
		}
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
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	var mecHosts []*models.MecHost
	_, _ = c.Db.QueryTable(util.Mec_Host, &mecHosts, "")
	for _, mecHost := range mecHosts {
		_, _ = c.Db.LoadRelated(mecHost, "Hwcapabilities")
	}
	var mecHostsRes []models.MecHostInfo
	res, err := json.Marshal(mecHosts)
	if err != nil {
		c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
		return
	}
	err = json.Unmarshal(res, &mecHostsRes)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}
	response, err := json.Marshal(mecHostsRes)
	if err != nil {
		c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
		return
	}
	_, _ = c.Ctx.ResponseWriter.Write(response)
	c.handleLoggingForSuccess(clientIp, "Query MEC host info is successful")
}

// @Title Query AppInstance information
// @Description AppInstance information
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances [get]
func (c *MecHostController) GetAppInstance() {
	log.Info("Query app instance request received.")
	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	tenantId, err := c.getTenantId(clientIp)
	if err != nil {
		return
	}

	var appInfoRecords []*models.AppInfoRecord
	var appInfoRec []*models.AppInfoRec
	_, _ = c.Db.QueryTable("app_info_record", &appInfoRecords, util.TenantId, tenantId)
	res, err := json.Marshal(appInfoRecords)
	if err != nil {
		return
	}
	err = json.Unmarshal(res, &appInfoRec)
	if err != nil {
		return
	}
	response, err := json.Marshal(appInfoRec)
	if err != nil {
		return
	}
	_, _ = c.Ctx.ResponseWriter.Write(response)
	c.handleLoggingForSuccess(clientIp, "Query App Instance info is successful")
}

// @Title Batch terminate application
// @Description Batch terminate application
// @Param   tenantId    path 	string	                  true   "tenantId"
// @Param   body        body    models.AppInstancesInfo   true   "The comma separated appinstances id's"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/batchTerminate [delete]
func (c *MecHostController) BatchTerminate() {
	log.Info("Batch terminate request received.")

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	_, err = c.getTenantId(clientIp)
	if err != nil {
		return
	}

	var request models.AppInstancesInfo
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &request)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}

	listOfAppIds := strings.Split(request.AppInstances, ",")
	for _, appInsId := range listOfAppIds {
		err = util.ValidateUUID(appInsId)
		if err != nil {
			c.HandleLoggingForError(clientIp, util.BadRequest, "App instance is invalid")
			return
		}

		err = c.TerminateApplication(clientIp, appInsId)
		if err != nil {
			return
		}
	}
	c.handleLoggingForSuccess(clientIp, "Batch termination is successful")
	c.ServeJSON()
}

// @Title Sync mec host records
// @Description Sync mec host records
// @Success 200 ok
// @Failure 400 bad request
// @router /hosts/sync_updated [get]
func (c *MecHostController) SynchronizeMecHostUpdatedRecord() {
	log.Info("Sync mec hosts request received.")

	var mecHosts []*models.MecHost
	var mecHostsSync []*models.MecHost
	var mecHostsRes []models.MecHostInfo
	var mecHostSyncRecords models.MecHostUpdatedRecords

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	_, _ = c.Db.QueryTable(util.Mec_Host, &mecHosts, "")
	for _, mecHost := range mecHosts {
		if !mecHost.SyncStatus && strings.EqualFold(mecHost.Origin, "mepm") {
			_, _ = c.Db.LoadRelated(mecHost, "Hwcapabilities")
			mecHostsSync = append(mecHostsSync, mecHost)
		}
	}

	res, err := json.Marshal(mecHostsSync)
	if err != nil {
		c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
		return
	}
	err = json.Unmarshal(res, &mecHostsRes)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}

	mecHostSyncRecords.MecHostUpdatedRecs = append(mecHostSyncRecords.MecHostUpdatedRecs, mecHostsRes...)

	response, err := json.Marshal(mecHostSyncRecords)
	if err != nil {
		c.writeErrorResponse(util.FailedToMarshal, util.BadRequest)
		return
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)
	_, err = c.Ctx.ResponseWriter.Write(response)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	for _, mecHost := range mecHostsSync {
		mecHost.SyncStatus = true
		err = c.Db.InsertOrUpdateData(mecHost, util.HostIp)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			log.Error("Failed to save mec host info record to database.")
			return
		}
	}
	c.handleLoggingForSuccess(clientIp, "Mec hosts synchronization is successful")
}

// @Title Sync mec host stale records
// @Description Sync mec host stale records
// @Success 200 ok
// @Failure 400 bad request
// @router /hosts/sync_deleted [get]
func (c *MecHostController) SynchronizeMecHostStaleRecord() {
	log.Info("Sync mec host stale request received.")

	var mecHostStaleRecs []models.MecHostStaleRec
	var mecHostStaleRecords models.MecHostStaleRecords

	clientIp := c.Ctx.Input.IP()
	err := util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return
	}
	c.displayReceivedMsg(clientIp)

	_, _ = c.Db.QueryTable("mec_host_stale_rec", &mecHostStaleRecs, "")

	mecHostStaleRecords.MecHostStaleRecs = append(mecHostStaleRecords.MecHostStaleRecs, mecHostStaleRecs...)
	res, err := json.Marshal(mecHostStaleRecords)
	if err != nil {
		c.writeErrorResponse("failed to marshal request", util.BadRequest)
		return
	}

	c.Ctx.ResponseWriter.Header().Set(util.ContentType, util.ApplicationJson)
	c.Ctx.ResponseWriter.Header().Set(util.Accept, util.ApplicationJson)
	_, err = c.Ctx.ResponseWriter.Write(res)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return
	}
	for _, mecHostStaleRec := range mecHostStaleRecs {
		err = c.Db.DeleteData(&mecHostStaleRec, util.HostIp)
		if err != nil && err.Error() != util.LastInsertIdNotSupported {
			c.HandleLoggingForError(clientIp, util.StatusInternalServerError, err.Error())
			return
		}
	}
	c.handleLoggingForSuccess(clientIp, "Stale mec host records synchronization is successful")
}

// Validate mec host, zip code and city
func (c *MecHostController) validateMecHostZipCodeCity(request models.MecHostInfo, clientIp string) error {
	hostName, err := util.ValidateName(request.MechostName, util.NameRegex)
	if err != nil || !hostName {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Mec host name is invalid")
		return err
	}

	zipcode, err := util.ValidateName(request.ZipCode, util.NameRegex)
	if err != nil || !zipcode {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Zipcode is invalid")
		return err
	}

	city, err := util.ValidateName(request.City, util.CityRegex)
	if err != nil || !city {
		c.HandleLoggingForError(clientIp, util.BadRequest, "City is invalid")
		return err
	}
	return nil
}
