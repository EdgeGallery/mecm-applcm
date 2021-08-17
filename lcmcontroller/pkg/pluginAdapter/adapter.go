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
	log.Info("Instantiation started")
	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.Instantiate(ctx, tenantId, accessToken, appInsId, req)
	if err != nil {
		log.Error("failed to instantiate application")
		return err, util.Failure
	}
	log.Info("instantiation completed with status: ", status)
	return nil, status
}

// Query application
func (c *PluginAdapter) Query(accessToken, appInsId, host string) (response string, error error) {
	log.Info("Query started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.Query(ctx, accessToken, appInsId, host)
	if err != nil {
		log.Errorf("failed to query information")
		return "", err
	}
	log.Info("Query completed with status: Success")
	return response, nil
}


// Query application
func (c *PluginAdapter) QueryKPI(accessToken, host string) (response string, error error) {
	log.Info("Query KPI started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.QueryKPI(ctx, accessToken, host)
	if err != nil {
		log.Errorf("failed to query kpi information")
		return "", err
	}
	log.Info("Query kpi completed with status: Success")
	return response, nil
}

// Terminate application
func (c *PluginAdapter) Terminate(host string, accessToken string, appInsId string) (status string, error error) {
	log.Info("Terminate started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.Terminate(ctx, host, accessToken, appInsId)
	if err != nil {
		log.Error("failed to terminate application")
		return util.Failure, err
	}

	log.Info("termination completed with status: ", status)
	return status, nil
}

// Upload configuration
func (c *PluginAdapter) UploadConfig(file multipart.File, host string, accessToken string) (status string,
	error error) {
	log.Info("Upload config started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.UploadConfig(ctx, file, host, accessToken)
	if err != nil {
		log.Error("failed to upload configuration")
		return util.Failure, err
	}

	log.Info("upload configuration is success with status: ", status)
	return status, nil
}

// Remove configuration
func (c *PluginAdapter) RemoveConfig(host string, accessToken string) (status string, error error) {
	log.Info("Remove config started")
	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.RemoveConfig(ctx, host, accessToken)
	if err != nil {
		log.Error("failed to remove configuration")
		return util.Failure, err
	}

	log.Info("remove configuration is success with status: ", status)
	return status, nil
}

// Get workload description
func (c *PluginAdapter) GetWorkloadDescription(accessToken, host, appInsId string) (response string, error error) {
	log.Info("Get workload description started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.WorkloadDescription(ctx, accessToken, appInsId, host)
	if err != nil {
		log.Errorf("failed to get workload description")
		return "", err
	}
	log.Info("Queried workload description completed with status: Success")
	return response, nil
}

// Create VM Image
func (c *PluginAdapter) CreateVmImage(host string, accessToken string, appInsId string, vmId string) (response string, error error) {
	log.Info("Create VM Image started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.CreateVmImage(ctx, accessToken, appInsId, host, vmId)
	if err != nil {
		log.Error("failed to create VM image")
		return util.Failure, err
	}

	log.Info("VM image creation completed with response: ", response)
	return response, nil
}

// Delete VM Image
func (c *PluginAdapter) DeleteVmImage(host string, accessToken string, appInsId string,
	imageId string) (status string, error error) {
	log.Info("Delete VM Image started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.DeleteVmImage(ctx, accessToken, appInsId, host, imageId)
	if err != nil {
		log.Error("failed to delete VM image")
		return util.Failure, err
	}

	log.Info("VM image deletion completed with status: ", status)
	return status, nil
}

// Query VM Image
func (c *PluginAdapter) QueryVmImage(host string, accessToken string, appInsId string,
	imageId string) (status string, error error) {
	log.Info("Query VM Image started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.QueryVmImage(ctx, accessToken, appInsId, host, imageId)
	if err != nil {
		log.Error("failed to query VM image")
		return util.Failure, err
	}

	log.Info("VM image query completed with response: ", response)
	return response, nil
}

// Query VM Image
func (c *PluginAdapter) DownloadVmImage(imgCtrlr *beegoCtx.Response, host string, accessToken string, appInsId string, imageId string,
	chunkNum int32) (buf *bytes.Buffer, error error) {
	log.Info("Download VM Image chunk started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Hour)
	defer cancel()

	response, err := c.client.DownloadVmImage(ctx, accessToken, appInsId, host, imageId, chunkNum)
	if err != nil {
		log.Error("failed to download VM image chunk")
		return response, err
	}

	log.Info("VM image chunk download completed successfully")
	return response, nil
}

// Upload configuration
func (c *PluginAdapter) UploadPackage(tenantId string, appPkg string, host string, packageId string,
	accessToken string) (status string, error error) {
	log.Info("Distribute package started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.UploadPackage(ctx, tenantId, appPkg, host, packageId, accessToken)
	if err != nil {
		log.Error("failed to upload Package")
		return util.Failure, err
	}

	log.Info("Package distribution is success with status: ", status)
	return status, nil
}

// Remove configuration
func (c *PluginAdapter) DeletePackage(tenantId string, host string, packageId string, accessToken string) (status string, error error) {
	log.Info("Delete package started")
	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.DeletePackage(ctx, tenantId, host, packageId, accessToken)
	if err != nil {
		log.Error("failed to remove configuration")
		return util.Failure, err
	}

	log.Info("remove configuration is success with status: ", status)
	return status, nil
}


// Upload configuration
func (c *PluginAdapter) UploadPackageStatus(tenantId string, host string, packageId string,
	accessToken string) (status string, error error) {
	log.Info("Upload package status started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.UploadPackageStatus(ctx, tenantId, host, packageId, accessToken)
	if err != nil {
		log.Error("failed to get upload Package status")
		return util.Failure, err
	}

	log.Info("Package status is success with status: ", status)
	return status, nil
}