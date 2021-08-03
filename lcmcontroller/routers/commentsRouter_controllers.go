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
	initAPI(util.Lcmcontroller, "AppDeploymentStatus", "/v1/hosts/:hostIp/packages/:packageId/status", util.GET)
	initAPI(util.Lcmcontroller, "HealthCheck", "/v1/health", util.GET)
	initAPI(util.Lcmcontroller, "UploadConfig", "/v1/configuration", util.POST)
	initAPI(util.Lcmcontroller, "RemoveConfig", "/v1/configuration", util.DELETE)
	initAPI(util.Lcmcontroller, "Instantiate", "/v1/tenants/:tenantId/app_instances/:appInstanceId/instantiate", util.POST)
	initAPI(util.Lcmcontroller, "Terminate", "/v1/tenants/:tenantId/app_instances/:appInstanceId/terminate", util.POST)
	initAPI(util.Lcmcontroller, "Query", "/v1/tenants/:tenantId/app_instances/:appInstanceId", util.GET)
	initAPI(util.Lcmcontroller, "QueryKPI", "/v1/tenants/:tenantId/hosts/:hostIp/kpi", util.GET)
	initAPI(util.Lcmcontroller, "QueryMepCapabilities", "/v1/tenants/:tenantId/hosts/:hostIp/mep_capabilities", util.GET)
	initAPI(util.Lcmcontroller, "QueryMepCapabilities", "/v1/tenants/:tenantId/hosts/:hostIp/mep_capabilities/:capabilityId", util.GET)
	initAPI(util.Lcmcontroller, "GetWorkloadDescription", "/v1/tenants/:tenantId/app_instances/:appInstanceId/workload/events", util.GET)
	initAPI(util.Lcmcontroller, "SynchronizeUpdatedRecord", "/v1/tenants/:tenantId/app_instances/sync_updated", util.GET)
	initAPI(util.Lcmcontroller, "SynchronizeStaleRecord", "/v1/tenants/:tenantId/app_instances/sync_deleted", util.GET)
	initAPI(util.Lcmcontroller, "UploadPackage", "/v1/tenants/:tenantId/packages", util.POST)
	initAPI(util.Lcmcontroller, "DeletePackage", util.PkgUrlPath, util.DELETE)
	initAPI(util.Lcmcontroller, "DeletePackageOnHost", "/v1/tenants/:tenantId/packages/:packageId/hosts/:hostIp", util.DELETE)
	initAPI(util.Lcmcontroller, "DistributePackage",   util.PkgUrlPath, util.POST)
	initAPI(util.Lcmcontroller, "DistributionStatus", util.PkgUrlPath, util.GET)
	initAPI(util.Lcmcontroller, "DistributionStatus", "/v1/tenants/:tenantId/packages", util.GET)
	initAPI(util.Lcmcontroller, "SynchronizeAppPackageUpdatedRecord","/v1/tenants/:tenantId/packages/sync_updated", util.GET)
	initAPI(util.Lcmcontroller, "SynchronizeAppPackageStaleRecord",  "/v1/tenants/:tenantId/packages/sync_deleted", util.GET)
	initAPI(util.Imagecontroller, "CreateImage", "/v1/tenants/:tenantId/app_instances/:appInstanceId/images", util.POST)
	initAPI(util.Imagecontroller, "DeleteImage", "/v1/tenants/:tenantId/app_instances/:appInstanceId/images/:imageId", util.DELETE)
	initAPI(util.Imagecontroller, "GetImage", "/v1/tenants/:tenantId/app_instances/:appInstanceId/images/:imageId", util.GET)
	initAPI(util.Imagecontroller, "GetImageFile", "/v1/tenants/:tenantId/app_instances/:appInstanceId/images/:imageId/file", util.GET)
	initAPI(util.MecHostcontroller, "AddMecHost", util.Hosts, util.POST)
	initAPI(util.MecHostcontroller, "UpdateMecHost", util.Hosts, "put")
	initAPI(util.MecHostcontroller, "GetMecHost", util.Hosts, util.GET)
	initAPI(util.MecHostcontroller, "DeleteMecHost", "/v1/hosts/:hostIp", util.DELETE)
	initAPI(util.MecHostcontroller, "GetAppInstance", "/v1/tenants/:tenantId/app_instances", util.GET)
	initAPI(util.MecHostcontroller, "BatchTerminate", "/v1/tenants/:tenantId/app_instances/batchTerminate", util.DELETE)
	initAPI(util.MecHostcontroller, "SynchronizeMecHostUpdatedRecord", "/v1/hosts/sync_updated", util.GET)
	initAPI(util.MecHostcontroller, "SynchronizeMecHostStaleRecord", "/v1/hosts/sync_deleted", util.GET)
	initAPI(util.Mepcontroller, "Services", "/v1/mep/services", util.GET)
	initAPI(util.Mepcontroller, "KongLog", "/v1/mep/kong_log", util.GET)
	initAPI(util.Mepcontroller, "Subscribe", "/v1/mep/subscribe_statistic", util.GET)



	initAPI(util.Lcmcontrollerv2, "UploadConfigV2", "/v2/configuration", util.POST)
	initAPI(util.Lcmcontrollerv2, "RemoveConfigV2", "/v2/configuration", util.DELETE)
	initAPI(util.Lcmcontrollerv2, "UploadPackageV2", "/v2/tenants/:tenantId/packages", util.POST)
	initAPI(util.Lcmcontrollerv2, "InstantiateV2", "/v2/tenants/:tenantId/app_instances/:appInstanceId/instantiate", util.POST)
	initAPI(util.Lcmcontrollerv2, "TerminateV2", "/v2/tenants/:tenantId/app_instances/:appInstanceId/terminate", util.POST)
	initAPI(util.Lcmcontrollerv2, "QueryV2", "/v2/tenants/:tenantId/app_instances/:appInstanceId", util.GET)
	initAPI(util.Lcmcontrollerv2, "QueryKPI", "/v2/tenants/:tenantId/hosts/:hostIp/kpi", util.GET)
	initAPI(util.Lcmcontrollerv2, "QueryMepCapabilities", "/v2/tenants/:tenantId/hosts/:hostIp/mep_capabilities", util.GET)
	initAPI(util.Lcmcontrollerv2, "QueryMepCapabilities", "/v2/tenants/:tenantId/hosts/:hostIp/mep_capabilities/:capabilityId", util.GET)
	initAPI(util.Lcmcontrollerv2, "GetWorkloadDescription", "/v2/tenants/:tenantId/app_instances/:appInstanceId/workload/events", util.GET)
	initAPI(util.Lcmcontrollerv2, "SynchronizeUpdatedRecord", "/v2/tenants/:tenantId/app_instances/sync_updated", util.GET)
	initAPI(util.Lcmcontrollerv2, "SynchronizeStaleRecord", "/v2/tenants/:tenantId/app_instances/sync_deleted", util.GET)
	//initAPI(util.Lcmcontrollerv2, "DeletePackage", util.PkgUrlPathV2, util.DELETE)
	//initAPI(util.Lcmcontrollerv2, "DeletePackageOnHost", "/v2/tenants/:tenantId/packages/:packageId/hosts/:hostIp", util.DELETE)
	//initAPI(util.Lcmcontrollerv2, "DistributePackage",   util.PkgUrlPathV2, util.POST)
	//initAPI(util.Lcmcontrollerv2, "DistributionStatus", util.PkgUrlPathV2, util.GET)
	//initAPI(util.Lcmcontrollerv2, "DistributionStatus", "/v2/tenants/:tenantId/packages", util.GET)
	//initAPI(util.Lcmcontrollerv2, "SynchronizeAppPackageUpdatedRecord","/v2/tenants/:tenantId/packages/sync_updated", util.GET)
	//initAPI(util.Lcmcontrollerv2, "SynchronizeAppPackageStaleRecord",  "/v2/tenants/:tenantId/packages/sync_deleted", util.GET)

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