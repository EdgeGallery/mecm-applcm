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

// Insert or update data into lcmbroker
func InsertOrUpdateData(data interface{}, cols ...string) (err error) {

	defer func() {
		if err := recover(); err != nil {
			log.Error("panic handled:", err)
			err = fmt.Errorf("recover panic as %s", err)
		}
	}()
	o := orm.NewOrm()
	err = o.Using(util.Default)
	if err != nil {
		return err
	}
	_, err = o.InsertOrUpdate(data, cols...)
	return err
}

// Read data from lcmbroker
func ReadData(data interface{}, cols ...string) (err error) {

	defer func() {
		if err := recover(); err != nil {
			log.Error("panic handled:", err)
			err = fmt.Errorf("recover panic as %s", err)
		}
	}()
	o := orm.NewOrm()
	err = o.Using(util.Default)
	if err != nil {
		return err
	}
	err = o.Read(data, cols...)
	return err
}