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
	"golang.org/x/net/context"
	"rescontroller/models"
)

// GRPC client APIs
type ClientIntf interface {
	CreateFlavor(ctx context.Context, flavor models.Flavor, hostIP, accessToken,
		tenantId string) (status string, error error)
	QueryFlavor(ctx context.Context, hostIP, accessToken, tenantId, flavorId string) (response string, error error)
	DeleteFlavor(ctx context.Context, hostIP, accessToken, tenantId, flavorId string) (response string, error error)
	CreateSecurityGroup(ctx context.Context, securityGroup models.SecurityGroup, hostIP, accessToken,
		tenantId string) (status string, error error)
	QuerySecurityGroup(ctx context.Context, hostIP, accessToken,
		tenantId, securityGroupId string) (response string, error error)
	DeleteSecurityGroup(ctx context.Context, hostIP, accessToken,
		tenantId, securityGroupId string) (response string, error error)
	CreateSecurityGroupRules(ctx context.Context, securityGroupRules models.SecurityGroupRules,
		hostIP, accessToken, tenantId string) (status string, error error)
	QuerySecurityGroupRules(ctx context.Context, hostIP, accessToken,
		tenantId, securityGroupId string) (response string, error error)
	DeleteSecurityGroupRule(ctx context.Context, hostIP, accessToken,
		tenantId, securityGroupRuleId string) (response string, error error)
	QueryImages(ctx context.Context, hostIP, accessToken,
		tenantId, imageId string) (response string, error error)
	DeleteImage(ctx context.Context, hostIP, accessToken,
		tenantId, imageId string) (response string, error error)
	CreateImage(ctx context.Context, image models.Image, hostIP, accessToken,
		tenantId string) (status string, error error)
	ImportImage(ctx context.Context, importImage models.ImportImage, hostIP, accessToken,
		tenantId string) (status string, error error)
	CreateServer(ctx context.Context, server models.Server, hostIP, accessToken,
		tenantId string) (status string, error error)
	QueryServer(ctx context.Context, hostIP, accessToken,
		tenantId, serverId string) (response string, error error)
	OperateServer(ctx context.Context, server models.OperateServer, hostIP, accessToken,
		tenantId, serverId string) (status string, error error)
	DeleteServer(ctx context.Context, hostIP, accessToken,
		tenantId, serverId string) (status string, error error)
}