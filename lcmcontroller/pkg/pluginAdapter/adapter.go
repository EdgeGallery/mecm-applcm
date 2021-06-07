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
package pluginAdapter

import (
	"bytes"
	"context"
	beegoCtx "github.com/astaxie/beego/context"
	"lcmcontroller/models"
	"lcmcontroller/util"
	"mime/multipart"
	"time"

	log "github.com/sirupsen/logrus"
)

// Plugin adapter which decides a specific client based on plugin info
type PluginAdapter struct {
	pluginInfo string
	client     ClientIntf
}

// Constructor of PluginAdapter
func NewPluginAdapter(pluginInfo string, client ClientIntf) *PluginAdapter {
	return &PluginAdapter{pluginInfo: pluginInfo, client: client}
}

// Instantiate application
func (c *PluginAdapter) Instantiate(tenantId string, accessToken string, appInsId string,
	req models.InstantiateRequest) (error error, status string) {
	log.Info("| adapter.go | Instantiate | Instantiation started")
	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.Instantiate(ctx, tenantId, accessToken, appInsId, req)
	if err != nil {
		log.Error("| adapter.go | Instantiate | failed to instantiate application")
		return err, util.Failure
	}
	log.Info("| adapter.go | Instantiate | instantiation completed with status: ", status)
	return nil, status
}

// Query application
func (c *PluginAdapter) Query(accessToken, appInsId, host string) (response string, error error) {
	log.Info("| adapter.go | Query | Query started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.Query(ctx, accessToken, appInsId, host)
	if err != nil {
		log.Errorf("| adapter.go | Query | failed to query information")
		return "", err
	}
	log.Info("| adapter.go | Query | Query completed with status: Success")
	return response, nil
}

// Terminate application
func (c *PluginAdapter) Terminate(host string, accessToken string, appInsId string) (status string, error error) {
	log.Info("| adapter.go | Terminate | Terminate started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.Terminate(ctx, host, accessToken, appInsId)
	if err != nil {
		log.Error("| adapter.go | Terminate | failed to terminate application")
		return util.Failure, err
	}

	log.Info("| adapter.go | Terminate | termination completed with status: ", status)
	return status, nil
}

// Upload configuration
func (c *PluginAdapter) UploadConfig(file multipart.File, host string, accessToken string) (status string,
	error error) {
	log.Info("| adapter.go | UploadConfig | Upload config started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.UploadConfig(ctx, file, host, accessToken)
	if err != nil {
		log.Error("| adapter.go | UploadConfig | failed to upload configuration")
		return util.Failure, err
	}

	log.Info("| adapter.go | UploadConfig | upload configuration is success with status: ", status)
	return status, nil
}

// Remove configuration
func (c *PluginAdapter) RemoveConfig(host string, accessToken string) (status string, error error) {
	log.Info("| adapter.go | RemoveConfig | Remove config started")
	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.RemoveConfig(ctx, host, accessToken)
	if err != nil {
		log.Error("| adapter.go | RemoveConfig | failed to remove configuration")
		return util.Failure, err
	}

	log.Info("| adapter.go | RemoveConfig | remove configuration is success with status: ", status)
	return status, nil
}

// Get workload description
func (c *PluginAdapter) GetWorkloadDescription(accessToken, host, appInsId string) (response string, error error) {
	log.Info("Get workload description started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.WorkloadDescription(ctx, accessToken, appInsId, host)
	if err != nil {
		log.Errorf("| adapter.go | CreateVmImage | failed to get workload description")
		return "", err
	}
	log.Info("| adapter.go | CreateVmImage | Queried workload description completed with status: Success")
	return response, nil
}

// Create VM Image
func (c *PluginAdapter) CreateVmImage(host string, accessToken string, appInsId string, vmId string) (response string, error error) {
	log.Info("| adapter.go | CreateVmImage | Create VM Image started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.CreateVmImage(ctx, accessToken, appInsId, host, vmId)
	if err != nil {
		log.Error("| adapter.go | CreateVmImage | failed to create VM image")
		return util.Failure, err
	}

	log.Info("| adapter.go | CreateVmImage | VM image creation completed with response: ", response)
	return response, nil
}

// Delete VM Image
func (c *PluginAdapter) DeleteVmImage(host string, accessToken string, appInsId string,
	imageId string) (status string, error error) {
	log.Info("| adapter.go | DeleteVmImage | Delete VM Image started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.DeleteVmImage(ctx, accessToken, appInsId, host, imageId)
	if err != nil {
		log.Error("| adapter.go | DeleteVmImage | failed to delete VM image")
		return util.Failure, err
	}

	log.Info("| adapter.go | DeleteVmImage | VM image deletion completed with status: ", status)
	return status, nil
}

// Query VM Image
func (c *PluginAdapter) QueryVmImage(host string, accessToken string, appInsId string,
	imageId string) (status string, error error) {
	log.Info("| adapter.go | QueryVmImage | Query VM Image started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.QueryVmImage(ctx, accessToken, appInsId, host, imageId)
	if err != nil {
		log.Error("| adapter.go | QueryVmImage | failed to query VM image")
		return util.Failure, err
	}

	log.Info("| adapter.go | QueryVmImage | VM image query completed with response: ", response)
	return response, nil
}

// Query VM Image
func (c *PluginAdapter) DownloadVmImage(imgCtrlr *beegoCtx.Response, host string, accessToken string, appInsId string, imageId string,
	chunkNum int32) (buf *bytes.Buffer, error error) {
	log.Info("| adapter.go | DownloadVmImage | Download VM Image chunk started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Hour)
	defer cancel()

	response, err := c.client.DownloadVmImage(ctx, accessToken, appInsId, host, imageId, chunkNum, imgCtrlr)
	if err != nil {
		log.Error("| adapter.go | DownloadVmImage | failed to download VM image chunk")
		return response, err
	}

	log.Info("| adapter.go | DownloadVmImage | VM image chunk download completed successfully")
	return response, nil
}

// Upload configuration
func (c *PluginAdapter) UploadPackage(tenantId string, appPkg string, host string, packageId string,
	accessToken string) (status string, error error) {
	log.Info("| adapter.go | UploadPackage | Distribute package started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.UploadPackage(ctx, tenantId, appPkg, host, packageId, accessToken)
	if err != nil {
		log.Error("| adapter.go | UploadPackage | failed to upload configuration")
		return util.Failure, err
	}

	log.Info("| adapter.go | UploadPackage | Package distribution success with status: ", status)
	return status, nil
}

// Remove configuration
func (c *PluginAdapter) DeletePackage(tenantId string, host string, packageId string, accessToken string) (status string, error error) {
	log.Info("| adapter.go | DeletePackage | Delete package started")
	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.DeletePackage(ctx, tenantId, host, packageId, accessToken)
	if err != nil {
		log.Error("| adapter.go | DeletePackage | failed to remove configuration")
		return util.Failure, err
	}

	log.Info("| adapter.go | DeletePackage | remove configuration success with status: ", status)
	return status, nil
}