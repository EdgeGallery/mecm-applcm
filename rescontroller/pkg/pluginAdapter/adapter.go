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

package pluginAdapter

import (
	"context"
	log "github.com/sirupsen/logrus"
	"rescontroller/models"
	"rescontroller/util"
	"time"
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

// Close connection
func (c *ClientGRPC) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// Create flavor
func (c *PluginAdapter) CreateFlavor(flavor models.Flavor, hostIp, accessToken, tenantId string) (status string,
	error error) {
	log.Info("Create flavor started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.CreateFlavor(ctx, flavor, hostIp, accessToken, tenantId)
	if err != nil {
		log.Error("failed to create flavor")
		return util.Failure, err
	}

	log.Info("Create flavor is success with status: ", status)
	return status, nil
}

// Query flavor
func (c *PluginAdapter) QueryFlavor(hostIp, accessToken, tenantId, flavorId string) (response string, error error) {
	log.Info("Query flavor started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.QueryFlavor(ctx, hostIp, accessToken, tenantId, flavorId)
	if err != nil {
		log.Error("failed to query flavor")
		return util.Failure, err
	}

	log.Info("Query flavor is success with status: success")
	return response, nil
}

// Delete flavor
func (c *PluginAdapter) DeleteFlavor(hostIp, accessToken, tenantId, flavorId string) (status string, error error) {
	log.Info("Delete flavor started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.DeleteFlavor(ctx, hostIp, accessToken, tenantId, flavorId)
	if err != nil {
		log.Error("failed to delete flavor")
		return util.Failure, err
	}

	log.Info("Delete flavor is success with status:", status)
	return status, nil
}

// Create security group
func (c *PluginAdapter) CreateSecurityGroup(securityGroup models.SecurityGroup, hostIp, accessToken, tenantId string) (status string,
	error error) {
	log.Info("Create security group started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.CreateSecurityGroup(ctx, securityGroup, hostIp, accessToken, tenantId)
	if err != nil {
		log.Error("failed to create security group")
		return util.Failure, err
	}

	log.Info("Create security group is success with status: ", status)
	return status, nil
}

// Query security group
func (c *PluginAdapter) QuerySecurityGroup(hostIp, accessToken, tenantId, securityGroupId string) (response string, error error) {
	log.Info("Query security group started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.QuerySecurityGroup(ctx, hostIp, accessToken, tenantId, securityGroupId)
	if err != nil {
		log.Error("failed to query security group")
		return util.Failure, err
	}

	log.Info("Query security group is success with status: success")
	return response, nil
}

// Delete flavor
func (c *PluginAdapter) DeleteSecurityGroup(hostIp, accessToken, tenantId, securityGroupId string) (status string, error error) {
	log.Info("Delete security group started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.DeleteSecurityGroup(ctx, hostIp, accessToken, tenantId, securityGroupId)
	if err != nil {
		log.Error("failed to delete security group")
		return util.Failure, err
	}

	log.Info("Delete security group is success with status:", status)
	return status, nil
}

// Create security group rules
func (c *PluginAdapter) CreateSecurityGroupRules(securityGroupRules models.SecurityGroupRules, hostIp, accessToken, tenantId string) (status string,
	error error) {
	log.Info("Create security group rules started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.CreateSecurityGroupRules(ctx, securityGroupRules, hostIp, accessToken, tenantId)
	if err != nil {
		log.Error("failed to create security group rule")
		return util.Failure, err
	}

	log.Info("Create security group rule is success with status: ", status)
	return status, nil
}


// Query security group
func (c *PluginAdapter) QuerySecurityGroupRules(hostIp, accessToken, tenantId, securityGroupId string) (response string, error error) {
	log.Info("Query security group rules started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	response, err := c.client.QuerySecurityGroupRules(ctx, hostIp, accessToken, tenantId, securityGroupId)
	if err != nil {
		log.Error("failed to query security group rules")
		return util.Failure, err
	}

	log.Info("Query security group rules is success with status: success")
	return response, nil
}

// Delete flavor
func (c *PluginAdapter) DeleteSecurityGroupRule(hostIp, accessToken, tenantId, securityGroupRuleId string) (status string, error error) {
	log.Info("Delete security group rule started")

	ctx, cancel := context.WithTimeout(context.Background(), util.Timeout*time.Second)
	defer cancel()

	status, err := c.client.DeleteSecurityGroupRule(ctx, hostIp, accessToken, tenantId, securityGroupRuleId)
	if err != nil {
		log.Error("failed to delete security group rule")
		return util.Failure, err
	}

	log.Info("Delete security group rule is success with status:", status)
	return status, nil
}
