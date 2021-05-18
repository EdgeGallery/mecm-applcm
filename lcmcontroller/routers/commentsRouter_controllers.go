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
	initAPI(util.Lcmcontroller, "AppDeploymentStatus", "/hosts/:hostIp/packages/:packageId/status", util.GET)
	initAPI(util.Lcmcontroller, "HealthCheck", "/health", util.GET)
	initAPI(util.Lcmcontroller, "UploadConfig", "/configuration", util.POST)
	initAPI(util.Lcmcontroller, "RemoveConfig", "/configuration", util.DELETE)
	initAPI(util.Lcmcontroller, "Instantiate", "/tenants/:tenantId/app_instances/:appInstanceId/instantiate", util.POST)
	initAPI(util.Lcmcontroller, "Terminate", "/tenants/:tenantId/app_instances/:appInstanceId/terminate", util.POST)
	initAPI(util.Lcmcontroller, "Query", "/tenants/:tenantId/app_instances/:appInstanceId", util.GET)
	initAPI(util.Lcmcontroller, "QueryKPI", "/tenants/:tenantId/hosts/:hostIp/kpi", util.GET)
	initAPI(util.Lcmcontroller, "QueryMepCapabilities", "/tenants/:tenantId/hosts/:hostIp/mep_capabilities", util.GET)
	initAPI(util.Lcmcontroller, "QueryMepCapabilities", "/tenants/:tenantId/hosts/:hostIp/mep_capabilities/:capabilityId", util.GET)
	initAPI(util.Lcmcontroller, "GetWorkloadDescription", "/tenants/:tenantId/app_instances/:appInstanceId/workload/events", util.GET)
	initAPI(util.Lcmcontroller, "SynchronizeUpdatedRecord", "/tenants/:tenantId/app_instances/sync_updated", util.GET)
	initAPI(util.Lcmcontroller, "SynchronizeStaleRecord", "/tenants/:tenantId/app_instances/sync_deleted", util.GET)
	initAPI(util.Lcmcontroller, "UploadPackage", "/tenants/:tenantId/packages", util.POST)
	initAPI(util.Lcmcontroller, "DeletePackage", util.PkgUrlPath, util.DELETE)
	initAPI(util.Lcmcontroller, "DeletePackageOnHost", "/tenants/:tenantId/packages/:packageId/hosts/:hostIp", util.DELETE)
	initAPI(util.Lcmcontroller, "DistributePackage",   util.PkgUrlPath, util.POST)
	initAPI(util.Lcmcontroller, "DistributionStatus", util.PkgUrlPath, util.GET)
	initAPI(util.Lcmcontroller, "DistributionStatus", "/tenants/:tenantId/packages", util.GET)
	initAPI(util.Lcmcontroller, "SynchronizeAppPackageUpdatedRecord","/tenants/:tenantId/packages/sync_updated", util.GET)
	initAPI(util.Lcmcontroller, "SynchronizeAppPackageStaleRecord",  "/tenants/:tenantId/packages/sync_deleted", util.GET)
	initAPI(util.Imagecontroller, "CreateImage", "/tenants/:tenantId/app_instances/:appInstanceId/images", util.POST)
	initAPI(util.Imagecontroller, "DeleteImage", "/tenants/:tenantId/app_instances/:appInstanceId/images/:imageId", util.DELETE)
	initAPI(util.Imagecontroller, "GetImage", "/tenants/:tenantId/app_instances/:appInstanceId/images/:imageId", util.GET)
	initAPI(util.Imagecontroller, "GetImageFile", "/tenants/:tenantId/app_instances/:appInstanceId/images/:imageId/file", util.GET)
	initAPI(util.MecHostcontroller, "AddMecHost", util.Hosts, util.POST)
	initAPI(util.MecHostcontroller, "UpdateMecHost", util.Hosts, "put")
	initAPI(util.MecHostcontroller, "GetMecHost", util.Hosts, util.GET)
	initAPI(util.MecHostcontroller, "DeleteMecHost", "/hosts/:hostIp", util.DELETE)
	initAPI(util.MecHostcontroller, "GetAppInstance", "/tenants/:tenantId/app_instances", util.GET)
	initAPI(util.MecHostcontroller, "BatchTerminate", "/tenants/:tenantId/app_instances/batchTerminate", util.DELETE)
	initAPI(util.MecHostcontroller, "SynchronizeMecHostUpdatedRecord", "/hosts/sync_updated", util.GET)
	initAPI(util.MecHostcontroller, "SynchronizeMecHostStaleRecord", "/hosts/sync_deleted", util.GET)
	initAPI(util.Mepcontroller, "Services", "/mep/services", util.GET)
	initAPI(util.Mepcontroller, "Kong_log", "/mep/kong_log", util.GET)
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