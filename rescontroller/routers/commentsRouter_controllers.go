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

package routers

import (
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context/param"
	"rescontroller/util"
)

func init() {
	initAPI(util.Flavorcontroller, "HealthCheck", "/v1/health", util.GET)

	initAPI(util.Flavorcontroller, "CreateFlavor", "/v1/tenants/:tenantId/hosts/:hostIp/flavors", util.POST)
	initAPI(util.Flavorcontroller, "QueryFlavor", "/v1/tenants/:tenantId/hosts/:hostIp/flavors", util.GET)
	initAPI(util.Flavorcontroller, "QueryFlavor", "/v1/tenants/:tenantId/hosts/:hostIp/flavors/:flavorId", util.GET)
	initAPI(util.Flavorcontroller, "DeleteFlavor", "/v1/tenants/:tenantId/hosts/:hostIp/flavors/:flavorId", util.DELETE)

	initAPI(util.Networkcontroller, "CreateNetwork", "/v1/tenants/:tenantId/hosts/:hostIp/networks", util.POST)
	initAPI(util.Networkcontroller, "QueryNetwork", "/v1/tenants/:tenantId/hosts/:hostIp/networks", util.GET)
	initAPI(util.Networkcontroller, "QueryNetwork", "/v1/tenants/:tenantId/hosts/:hostIp/networks/:networkId", util.GET)
	initAPI(util.Networkcontroller, "DeleteNetwork", "/v1/tenants/:tenantId/hosts/:hostIp/networks/:networkId", util.DELETE)

	initAPI(util.SecurityGroupcontroller, "CreateSecurityGroup", "/v1/tenants/:tenantId/hosts/:hostIp/securityGroups", util.POST)
	initAPI(util.SecurityGroupcontroller, "QuerySecurityGroup", "/v1/tenants/:tenantId/hosts/:hostIp/securityGroups", util.GET)
	initAPI(util.SecurityGroupcontroller, "QuerySecurityGroup", "/v1/tenants/:tenantId/hosts/:hostIp/securityGroups/:securityGroupId", util.GET)
	initAPI(util.SecurityGroupcontroller, "DeleteSecurityGroup", "/v1/tenants/:tenantId/hosts/:hostIp/securityGroups/:securityGroupId", util.DELETE)
	initAPI(util.SecurityGroupcontroller, "CreateSecurityGroupRules", "/v1/tenants/:tenantId/hosts/:hostIp/securityGroups/:securityGroupId/securityGroupRules", util.POST)
	initAPI(util.SecurityGroupcontroller, "DeleteSecurityGroupRules", "/v1/tenants/:tenantId/hosts/:hostIp/securityGroups/:securityGroupId/securityGroupRules/:securityGroupRuleId", util.DELETE)

	initAPI(util.VmImagecontroller, "QueryImages", "/v1/tenants/:tenantId/hosts/:hostIp/images", util.GET)
	initAPI(util.VmImagecontroller, "QueryImages", util.QueryImages, util.GET)
	initAPI(util.VmImagecontroller, "DeleteImage", util.QueryImages, util.DELETE)
	initAPI(util.VmImagecontroller, "CreateImage", "/v1/tenants/:tenantId/hosts/:hostIp/images", util.POST)
	initAPI(util.VmImagecontroller, "ImportImage",  util.QueryImages, util.POST)

	initAPI(util.VmController, "CreateServer", "/v1/tenants/:tenantId/hosts/:hostIp/servers", util.POST)
	initAPI(util.VmController, "QueryServer", "/v1/tenants/:tenantId/hosts/:hostIp/servers", util.GET)
	initAPI(util.VmController, "QueryServer", util.QueryServer, util.GET)
	initAPI(util.VmController, "OperateServer", util.QueryServer, util.POST)
	initAPI(util.VmController, "DeleteServer", util.QueryServer, util.DELETE)
}

func initAPI(controllerName, methodName, path, operationType string,) {
	beego.GlobalControllerRouter[controllerName] = append(beego.GlobalControllerRouter[controllerName],
		beego.ControllerComments{
			Method:           methodName,
			Router:           path,
			AllowHTTPMethods: []string{operationType},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
}
