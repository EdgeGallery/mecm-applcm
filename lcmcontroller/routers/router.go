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
// @APIVersion 1.0.0
// @Title Lcm Controller API
// @Description beego has a very cool tools to autogenerate documents for your API
// @TermsOfServiceUrl http://beego.me/
package routers

import (
	"github.com/astaxie/beego"
	"lcmcontroller/controllers"
	"lcmcontroller/pkg/dbAdapter"
	"os"
)

const RootPath string = "/lcmcontroller/v1"

// Init lcmcontroller APIs
func init() {
	adapter := initDbAdapter()

	ns := beego.NewNamespace("/lcmcontroller/v1/",
		beego.NSInclude(
			&controllers.LcmController{controllers.BaseController{Db: adapter}},
			&controllers.ImageController{controllers.BaseController{Db: adapter}},
			&controllers.MecHostController{controllers.BaseController{Db: adapter}},
			&controllers.MecController{controllers.BaseController{Db: adapter}},
		),
	)
	beego.AddNamespace(ns)

}

// Init Db adapter
func initDbAdapter() (pgDb dbAdapter.Database) {
	adapter, err := dbAdapter.GetDbAdapter()
	if err != nil {
		os.Exit(1)
	}
	return adapter
}
