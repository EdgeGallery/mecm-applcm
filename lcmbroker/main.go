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

package main

import (
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/astaxie/beego/orm"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	_ "lcmbroker/config"
	"lcmbroker/controllers"
	_ "lcmbroker/models"
	_ "lcmbroker/routers"
	"lcmbroker/util"
	"os"
	"strings"
	"unsafe"
)

func initDatabase() error {
	dbUser := os.Getenv("dbUser")
	dbPwd := os.Getenv("dbPwd")
	dbName := os.Getenv("dbName")
	dbHost := os.Getenv("dbHost")
	dbPort := os.Getenv("dbPort")
	dbSslMode := os.Getenv("dbSslMode")
	dbSslRootCert := os.Getenv("db_sslrootcert")

	dbParamsAreValid, validateDbParamsErr := util.ValidateDbParams(dbUser, dbPwd, dbName, dbHost, dbPort)
	if validateDbParamsErr != nil || !dbParamsAreValid {
		return validateDbParamsErr
	}
	registerDriverErr := orm.RegisterDriver("postgres", orm.DRPostgres)
	if registerDriverErr != nil {
		logs.Error("Failed to register driver")
		return registerDriverErr
	}

	var b strings.Builder
	fmt.Fprintf(&b, "user=%s password=%s dbname=%s host=%s port=%s sslmode=%s sslrootcert=%s", dbUser, dbPwd,
		dbName, dbHost, dbPort, dbSslMode, dbSslRootCert)
	bStr := b.String()

	registerDataBaseErr := orm.RegisterDataBase("default", "postgres", bStr)
	//clear bStr
	bKey1 := *(*[]byte)(unsafe.Pointer(&bStr))
	for i := 0; i < len(bKey1); i++ {
		bKey1[i] = 0
	}

	if registerDataBaseErr != nil {
		logs.Error("Failed to register database")
		return registerDataBaseErr
	}
	errRunSyncdb := orm.RunSyncdb("default", false, false)
	if errRunSyncdb != nil {
		logs.Error("Failed to sync database.")
		return errRunSyncdb
	}

	return nil
}


func main() {
	err := initDatabase()
	if err != nil {
		log.Error("Failed to init database.")
		return
	}
	beego.ErrorController(&controllers.ErrorController{})
	beego.Run()
}
