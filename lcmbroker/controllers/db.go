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

package controllers

import (
	"fmt"
	"github.com/astaxie/beego/orm"
	log "github.com/sirupsen/logrus"
	"lcmbroker/util"
	"strings"
	"unsafe"
)

// Init database
func init() {
	dbUser := os.Getenv("dbUser")
	dbPwd := os.Getenv("dbPwd")
	dbName := os.Getenv("dbName")
	dbHost := os.Getenv("dbHost")
	dbPort := os.Getenv("dbPort")
	dbSslMode := os.Getenv("dbSslMode")
	dbSslRootCert := os.Getenv("db_sslrootcert")


	dbParamsAreValid, validateDbParamsErr := util.ValidateDbParams(dbUser, dbPwd, dbName, dbHost, dbPort)
	if validateDbParamsErr != nil || !dbParamsAreValid {
		return
	}
	registerDriverErr := orm.RegisterDriver(util.DriverName, orm.DRPostgres)
	if registerDriverErr != nil {
		log.Error("Failed to register driver")
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "user=%s password=%s dbname=%s host=%s port=%s sslmode=%s sslrootcert=%s", dbUser, dbPwd,
		dbName, dbHost, dbPort, dbSslMode, dbSslRootCert)
	bStr := b.String()

	registerDataBaseErr := orm.RegisterDataBase(util.Default, util.DriverName, bStr)
	//clear bStr
	bKey1 := *(*[]byte)(unsafe.Pointer(&bStr))
	util.ClearByteArray(bKey1)

	if registerDataBaseErr != nil {
		log.Error("Failed to register database")
		return
	}
	errRunSyncdb := orm.RunSyncdb(util.Default, false, false)
	if errRunSyncdb != nil {
		log.Error("Failed to sync database.")
		return
	}

	return
}

// Database API's
type Database interface {
	InsertOrUpdateData(data interface{}, cols ...string) (err error)
	ReadData(data interface{}, cols ...string) (err error)
}