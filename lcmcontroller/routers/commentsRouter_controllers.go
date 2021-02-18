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
	"lcmcontroller/util"
)

func init() {
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "AppDeploymentStatus",
			Router:           "/hosts/:hostIp/packages/:packageId/status",
			AllowHTTPMethods: []string{"get"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "HealthCheck",
			Router:           "/health",
			AllowHTTPMethods: []string{"get"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "UploadConfig",
			Router:           "/configuration",
			AllowHTTPMethods: []string{"post"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "RemoveConfig",
			Router:           "/configuration",
			AllowHTTPMethods: []string{"delete"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "Instantiate",
			Router:           "/tenants/:tenantId/app_instances/:appInstanceId/instantiate",
			AllowHTTPMethods: []string{"post"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "Terminate",
			Router:           "/tenants/:tenantId/app_instances/:appInstanceId/terminate",
			AllowHTTPMethods: []string{"post"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "Query",
			Router:           "/tenants/:tenantId/app_instances/:appInstanceId",
			AllowHTTPMethods: []string{"get"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "QueryKPI",
			Router:           "/tenants/:tenantId/hosts/:hostIp/kpi",
			AllowHTTPMethods: []string{"get"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "QueryMepCapabilities",
			Router:           "/tenants/:tenantId/hosts/:hostIp/mep_capabilities",
			AllowHTTPMethods: []string{"get"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "QueryMepCapabilities",
			Router:           "/tenants/:tenantId/hosts/:hostIp/mep_capabilities/:capabilityId",
			AllowHTTPMethods: []string{"get"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
	beego.GlobalControllerRouter[util.Lcmcontroller] = append(beego.GlobalControllerRouter[util.Lcmcontroller],
		beego.ControllerComments{
			Method:           "GetPodDescription",
			Router:           "/tenants/:tenantId/app_instances/:appInstanceId/pods/desc",
			AllowHTTPMethods: []string{"get"},
			MethodParams:     param.Make(),
			Filters:          nil,
			Params:           nil})
}
