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
package controllers

import (
	"fmt"
	"github.com/astaxie/beego/orm"
	log "github.com/sirupsen/logrus"
	"lcmbroker/util"
)

// Pg database
type PgDb struct {
	 ormer orm.Ormer
}

// Constructor of PluginAdapter
func NewPgDbAdapter() (pgDb *PgDb, err error) {
	defer func() {
		if err := recover(); err != nil {
			log.Error("panic handled:", err)
			err = fmt.Errorf("recover panic as %s", err)
		}
	}()
	o := orm.NewOrm()
	err = o.Using(util.Default)
	if err != nil {
		return nil, err
	}

	return &PgDb{ormer: o}, nil
}

// Insert or update data into lcmbroker
func (db *PgDb) InsertOrUpdateData(data interface{}, cols ...string) (err error) {
	_, err = db.ormer.InsertOrUpdate(data, cols...)
	return err
}

// Read data from lcmbroker
func (db *PgDb)  ReadData(data interface{}, cols ...string) (err error) {
	err = db.ormer.Read(data, cols...)
	return err
}