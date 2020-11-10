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
	"context"
	"lcmcontroller/config"
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
func (c *PluginAdapter) Instantiate(host string, deployArtifact string,
	accessToken string, akSkAppInfo config.AppAuthConfig) (error error, status string) {
	log.Info("Instantiation started")
	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.Instantiate(ctx, deployArtifact, host, accessToken, akSkAppInfo)
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
func (c *PluginAdapter) UploadConfig(file multipart.File, host string, accessToken string) (status string, error error) {
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
