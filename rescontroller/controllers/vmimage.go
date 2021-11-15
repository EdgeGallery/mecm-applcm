/*
 * Copyright 2021 Huawei Technologies Co., Ltd.
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

package controllers

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"rescontroller/models"
	"rescontroller/util"
	"unsafe"
)

// vm image Controller
type VmImageController struct {
	BaseController
}

// @Title Query Images
// @Description Query Images
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   imageId       path 	     string	true   "imageId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/images/:imageId [get]
func (c *VmImageController) QueryImages() {
	log.Info("Query images request received.")
	var imageId = ""

	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	if c.IsIdAvailable(":imageId") {
		imageId = c.GetId(":imageId")
	}

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}

	response, err := adapter.QueryImages(hostIp, accessToken, tenantId, imageId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeInternalServer)
		return
	}
	c.handleLoggingForSuccessV1(clientIp, "Query security group is successful")
}

// @Title Delete Image
// @Description Delete Image
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   imageId       path 	     string	true   "imageId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/images/:imageId [delete]
func (c *VmImageController) DeleteImage() {
	log.Info("Delete image request received.")

	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	imageId := c.GetId(":imageId")

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}

	_, err = adapter.DeleteImage(hostIp, accessToken, tenantId, imageId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	c.handleLoggingForSuccess(nil, clientIp, "Delete image is successful")
}

// @Title Create Image
// @Description Create Image
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   imageId       path 	     string	true   "imageId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/images/:imageId [post]
func (c *VmImageController) CreateImage() {
	log.Info("Create image request received.")
	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	var image models.Image
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &image)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}

	response, err := adapter.CreateImage(image, hostIp, accessToken, tenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeInternalServer)
		return
	}
	c.handleLoggingForSuccessV1(clientIp, "Create image is successful")
}

// @Title Import Image
// @Description Import Image
// @Param   access_token  header     string true   "access token"
// @Param   tenantId      path 	     string	true   "tenantId"
// @Param   hostIp        path 	     string	true   "hostIp"
// @Param   imageId       path 	     string	true   "imageId"
// @Success 200 ok
// @Failure 400 bad request
// @router /tenants/:tenantId/hosts/:hostIp/images/:imageId [post]
func (c *VmImageController) ImportImage() {
	log.Info("Import image request received.")
	err, accessToken, clientIp, hostIp, vim, tenantId := c.ValidateAccessTokenAndGetInputParameters([]string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		return
	}
	bKey := *(*[]byte)(unsafe.Pointer(&accessToken))
	defer util.ClearByteArray(bKey)

	adapter, err := c.GetAdapter(clientIp, vim)
	if err != nil {
		return
	}

	var importImage models.ImportImage
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &importImage)
	if err != nil {
		c.writeErrorResponse(util.FailedToUnmarshal, util.BadRequest)
		return
	}
	response, err := adapter.ImportImage(importImage, hostIp, accessToken, tenantId)
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.PluginErrorReport,
			util.ErrCodePluginReportFailed)
		return
	}
	_, err = c.Ctx.ResponseWriter.Write([]byte(response))
	if err != nil {
		c.HandleForErrorCode(clientIp, util.StatusInternalServerError, util.FailedToWriteRes, util.ErrCodeInternalServer)
		return
	}
	c.handleLoggingForSuccessV1(clientIp, "Import image is successful")
}
