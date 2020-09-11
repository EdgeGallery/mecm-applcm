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

// db controller
package pgdb

import (
	"errors"
	"fmt"
	"k8splugin/util"
	"os"
	"strings"
	"unsafe"

	"github.com/astaxie/beego/orm"
	log "github.com/sirupsen/logrus"
)

// Variables are required for db connections
var (
	DB_SSL_MODE     = "enable"
	DB_SSL_ROOT_CER = "ssl/ca.crt"
)

// Pg database
type PgDb struct {
	ormer orm.Ormer
}

// Constructor of PluginAdapter
func (db *PgDb) initOrmer() (err1 error) {
	defer func() {
		if err := recover(); err != nil {
			log.Error("panic handled:", err)
			err1 = fmt.Errorf("recover panic as %s", err)
		}
	}()
	o := orm.NewOrm()
	err1 = o.Using(util.Default)
	if err1 != nil {
		return err1
	}
	db.ormer = o

	return nil
}

// Insert or update data into k8splugin
func (db *PgDb) InsertOrUpdateData(data interface{}, cols ...string) (err error) {
	_, err = db.ormer.InsertOrUpdate(data, cols...)
	return err
}

// Read data from k8splugin
func (db *PgDb) ReadData(data interface{}, cols ...string) (err error) {
	err = db.ormer.Read(data, cols...)
	return err
}

// Delete data from k8splugin
func (db *PgDb) DeleteData(data interface{}, cols ...string) (err error) {
	_, err = db.ormer.Delete(data, cols...)
	return err
}

// Init database
func (db *PgDb) InitDatabase() error {
	dbUser := util.GetDbUser()
	dbPwd := os.Getenv("K8S_PLUGIN_DB_PASSWORD")
	dbName := util.GetDbName()
	dbHost := util.GetDbHost()
	dbPort := util.GetDbPort()
	dbSslMode := DB_SSL_MODE
	dbSslRootCert := DB_SSL_ROOT_CER

	dbParamsAreValid, validateDbParamsErr := util.ValidateDbParams(dbUser, dbPwd, dbName, dbHost, dbPort)
	if validateDbParamsErr != nil || !dbParamsAreValid {
		return errors.New("failed to validate db parameters")
	}
	registerDriverErr := orm.RegisterDriver(util.DriverName, orm.DRPostgres)
	if registerDriverErr != nil {
		log.Error("Failed to register driver")
		return registerDriverErr
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
		return registerDataBaseErr
	}
	errRunSyncdb := orm.RunSyncdb(util.Default, false, false)
	if errRunSyncdb != nil {
		log.Error("Failed to sync database.")
		return errRunSyncdb
	}
	err := db.initOrmer()
	if err != nil {
		log.Error("Failed to init ormer")
		return err
	}
	return nil
}
