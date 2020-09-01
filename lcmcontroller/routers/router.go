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
	"lcmcontroller/controllers"
)

const RootPath string = "/lcmcontroller/v1"

// Init lcmcontroller APIs
func init() {
	beego.Router(RootPath+"/configuration", &controllers.LcmController{}, "post:UploadConfig")
	beego.Router(RootPath+"/configuration", &controllers.LcmController{}, "delete:RemoveConfig")
	beego.Router(RootPath+"/app_instances/:appInstanceId/instantiate", &controllers.LcmController{}, "post:Instantiate")
	beego.Router(RootPath+"/app_instances/:appInstanceId/terminate", &controllers.LcmController{}, "post:Terminate")
	beego.Router(RootPath+"/app_instances/:appInstanceId", &controllers.LcmController{}, "get:Query")
	beego.Router(RootPath+"/kpi/:hostIp", &controllers.LcmController{}, "get:QueryKPI")
	beego.Router(RootPath+"/mep_capabilities/:hostIp", &controllers.LcmController{}, "get:QueryMepCapabilities")
}