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

// LCM broker APIs
package routers

import (
	"github.com/astaxie/beego"
	log "github.com/sirupsen/logrus"
	"lcmcontroller/controllers"
	"lcmcontroller/pkg/dbAdapter"
	"os"
)

const RootPath string = "/lcmcontroller/v1"

// Init lcmcontroller APIs
func init() {
	adapter := initDbAdapter()
	beego.Router(RootPath+"/configuration", &controllers.LcmController{}, "post:UploadConfig")
	beego.Router(RootPath+"/configuration", &controllers.LcmController{}, "delete:RemoveConfig")
	beego.Router(RootPath+"/tenants/:tenantId/app_instances/:appInstanceId/instantiate",
		&controllers.LcmController{Db: adapter}, "post:Instantiate")
	beego.Router(RootPath+"/tenants/:tenantId/app_instances/:appInstanceId/terminate",
		&controllers.LcmController{Db: adapter}, "post:Terminate")
	beego.Router(RootPath+"/tenants/:tenantId/app_instances/:appInstanceId", &controllers.LcmController{Db: adapter},
		"get:Query")
	beego.Router(RootPath+"/tenants/:tenantId/hosts/:hostIp/kpi", &controllers.LcmController{},
		"get:QueryKPI")
	beego.Router(RootPath+"/tenants/:tenantId/hosts/:hostIp/mep_capabilities", &controllers.LcmController{},
		"get:QueryMepCapabilities")
}

// Init Db adapter
func initDbAdapter() (pgDb dbAdapter.Database) {
	adapter, err := dbAdapter.GetDbAdapter()
	if err != nil {
		log.Error("Failed to get database")
		os.Exit(1)
	}
	return adapter
}
