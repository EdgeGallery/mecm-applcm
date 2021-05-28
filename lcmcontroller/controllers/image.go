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

// Image controller
package controllers

import (
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"lcmcontroller/models"
	"lcmcontroller/pkg/pluginAdapter"
	"lcmcontroller/util"
	"strconv"
	"unsafe"
)

// Image Controller
type ImageController struct {
	BaseController
}

// @Title Create Image
// @Description creation of image
// @Param   tenantId        path 	string	true   "tenantId"
// @Param   appInstanceId   path 	string	true   "appInstanceId"
// @Param   access_token    header  string  true   "access token"
// @Param   vmId            body 	string	true   "vmId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/app_instances/:appInstanceId/images [post]
func (c *ImageController) CreateImage() {
	log.Info("Image creation request received.")

	accessToken, bKey, appInfoRecord, adapter, clientIp, err := c.getInputParams()
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	var request models.CreateVimRequest
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &request)
	if err != nil {
		c.writeErrorResponse("failed to unmarshal request", util.BadRequest)
		util.ClearByteArray(bKey)
		return
	}

	response, err := adapter.CreateVmImage(appInfoRecord.MecHost, accessToken, appInfoRecord.AppInstanceId, request.VmId)
	util.ClearByteArray(bKey)
	if err != nil {
		// To check if any more error code needs to be returned.
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		return
	}

	err = c.sendResponse(response, clientIp)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(clientIp, "VM Image creation is successful")
}


// @Title Delete Image
// @Description deletion of image
// @Param   tenantId        path 	string	true   "tenantId"
// @Param   appInstanceId   path 	string	true   "appInstanceId"
// @Param   imageId         path 	string	true   "imageId"
// @Param   access_token    header  string  true   "access token"
// @Success 200 ok
// @Failure 400 bad request
// @Failure 500 internal server error
// @router /tenants/:tenantId/app_instances/:appInstanceId/images/:imageId [delete]
func (c *ImageController) DeleteImage() {
	log.Info("Image deletion request received.")

	accessToken, bKey, appInfoRecord, adapter, clientIp, err := c.getInputParams()
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	imageId, err := c.getImgId(clientIp, bKey)
	if nil != err {
		return
	}

	_, err = adapter.DeleteVmImage(appInfoRecord.MecHost, accessToken, appInfoRecord.AppInstanceId, imageId)
	util.ClearByteArray(bKey)
	if err != nil {
		// To check if any more error code needs to be returned.
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		return
	}

	c.handleLoggingForSuccess(clientIp, "VM Image Deletion is successful")
	c.ServeJSON()
}

// @Title Query Image
// @Description query of image
// @Param   tenantId        path 	string	true   "tenantId"
// @Param   appInstanceId   path 	string	true   "appInstanceId"
// @Param   imageId         path 	string	true   "imageId"
// @Param   access_token    header  string  true   "access token"
// @Success 200 ok
// @Failure 400 bad request
// @Failure 500 internal server error
// @router /tenants/:tenantId/app_instances/:appInstanceId/images/:imageId [get]
func (c *ImageController) GetImage() {
	log.Info("Query image request received.")
	accessToken, bKey, appInfoRecord, adapter, clientIp, err := c.getInputParams()
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	imageId, err := c.getImgId(clientIp, bKey)
	if nil != err {
		return
	}

	response, err := adapter.QueryVmImage(appInfoRecord.MecHost, accessToken, appInfoRecord.AppInstanceId, imageId)
	util.ClearByteArray(bKey)
	if err != nil {
		// To check if any more error code needs to be returned.
		c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
		return
	}

	err = c.sendResponse(response, clientIp)
	if err != nil {
		return
	}

	c.handleLoggingForSuccess(clientIp, "VM Image query is successful")
}

// @Title Download Image file
// @Description download a specific chunk of image file
// @Param   tenantId        path 	string	true   "tenantId"
// @Param   appInstanceId   path 	string	true   "appInstanceId"
// @Param   imageId         path 	string	true   "imageId"
// @Param   access_token    header  string  true   "access token"
// @Param   chunk_num       header  string  true   "chunk number"
// @Success 200 ok
// @Failure 404 image or chunk doesn't exist
// @router /tenants/:tenantId/app_instances/:appInstanceId/images/:imageId/file [get]
func (c *ImageController) GetImageFile() {
	log.Info("Download image file request received.")

	accessToken, bKey, appInfoRecord, adapter, clientIp, err := c.getInputParams()
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	imageId, err := c.getImgId(clientIp, bKey)
	if nil != err {
		return
	}

	chunkNum, err := c.getChunkNum(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return
	}

	if chunkNum == 0 {
		responseWriter := c.Ctx.ResponseWriter
		_, err = adapter.DownloadVmImage(responseWriter, appInfoRecord.MecHost, accessToken, appInfoRecord.AppInstanceId, imageId,
			chunkNum)
		util.ClearByteArray(bKey)
		if err != nil {
			// To check if any more error code needs to be returned.
			c.HandleLoggingForError(clientIp, util.BadRequest, err.Error())
			return
		}
	}
	util.ClearByteArray(bKey)
	_, ok := util.VmImageMap[chunkNum]
	if ok {
		_, _ = c.Ctx.ResponseWriter.Write(util.VmImageMap[chunkNum])
		delete(util.VmImageMap, chunkNum)
		c.handleLoggingForSuccess(clientIp, "VM Image download chunk is successful")
	} else {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError,
			"data is not exist for given chunk number")
	}

}

// Get Image Id
func (c *ImageController) getImageId(clientIp string) (string, error) {
	imageId := c.Ctx.Input.Param(":imageId")
	if len(imageId) > util.MaxIdLength {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Image ID is invalid")
		return "", errors.New("Image ID is invalid")
	}
	return imageId, nil
}

// Get Chunk number
func (c *ImageController) getChunkNum(clientIp string) (int32, error) {
	chunkString := c.Ctx.Request.Header.Get("chunk_num")

	i, err := strconv.ParseInt(chunkString, 10, 32)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, "Chunk number is invalid")
		return 0, errors.New("Chunk number is invalid")
	}
	return int32(i), nil
}

func (c *ImageController) getInputParams() (accessToken string, bKey []byte, appInfoRecord *models.AppInfoRecord,
	adapter *pluginAdapter.PluginAdapter, clientIp string, err error) {
	clientIp = c.Ctx.Input.IP()
	err = util.ValidateSrcAddress(clientIp)
	if err != nil {
		c.HandleLoggingForError(clientIp, util.BadRequest, util.ClientIpaddressInvalid)
		return accessToken, bKey, appInfoRecord, adapter, clientIp, err
	}
	c.displayReceivedMsg(clientIp)
	accessToken = c.Ctx.Request.Header.Get(util.AccessToken)
	bKey = *(*[]byte)(unsafe.Pointer(&accessToken))
	_, err = c.isPermitted(accessToken, clientIp)
	if err != nil {
		return accessToken, bKey, appInfoRecord, adapter, clientIp, err
	}

	appInsId, err := c.getAppInstId(clientIp)
	if err != nil {
		return accessToken, bKey, appInfoRecord, adapter, clientIp, err
	}

	appInfoRecord, err = c.getAppInfoRecord(appInsId, clientIp)
	if err != nil {
		return accessToken, bKey, appInfoRecord, adapter, clientIp, err
	}

	vim, err := c.getVim(clientIp, appInfoRecord.MecHost)
	if err != nil {
		return accessToken, bKey, appInfoRecord, adapter, clientIp, err
	}

	adapter, err = c.getPluginAdapter(appInfoRecord.DeployType, clientIp, vim)
	if err != nil {
		return accessToken, bKey, appInfoRecord, adapter, clientIp, err
	}
	return accessToken, bKey, appInfoRecord, adapter, clientIp, nil
}

func (c *ImageController) getImgId(clientIp string, bKey []byte) (string, error) {
	imageId, err := c.getImageId(clientIp)
	if err != nil {
		util.ClearByteArray(bKey)
		return "", err
	}
	return imageId, nil
}

func (c *ImageController) sendResponse(response, clientIp string) error {
	_, err := c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleLoggingForError(clientIp, util.StatusInternalServerError, util.FailedToWriteRes)
		return err
	}
	return nil
}