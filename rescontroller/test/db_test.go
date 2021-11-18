/*
 * Copyright 2021 Huawei Technologies Co., Ltd.
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

package test

import (
	"errors"
	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/orm"
	"github.com/stretchr/testify/assert"
	"os"
	"reflect"
	_ "rescontroller/log"
	"rescontroller/pkg/dbAdapter"
	"testing"
)

const (
	LcmControllerDbPwd = "LCM_CNTLR_DB_PASSWORD"
	LcmControllerPwd   = "fe0Hmv%sbq"
)

func TestGetDbAdapterSuccess(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) (error) {
		// do nothing
		return nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) (error) {
		// do nothing
		return nil
	})
	defer patch2.Reset()

	var c *dbAdapter.PgDb
	patch3 := gomonkey.ApplyMethod(reflect.TypeOf(c), "InitOrmer", func(*dbAdapter.PgDb) (error) {
		go func() {
			// do nothing
		}()
		return nil
	})
	defer patch3.Reset()

	os.Setenv(LcmControllerDbPwd, LcmControllerPwd)
	_, err := dbAdapter.GetDbAdapter()
	assert.Error(t, err, "TestGetDbAdapterSuccess execution result")
	beego.AppConfig.Set("dbAdapter", "pgDb")
	_, err = dbAdapter.GetDbAdapter()
	assert.Nil(t, err, "TestGetDbAdapterSuccess execution result")
}

func TestInitDbSuccess(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDriver, func(_ string, _ orm.DriverType) error {
		// do nothing
		return nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) error {
		// do nothing
		return nil
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) error {
		// do nothing
		return nil
	})
	defer patch3.Reset()

	patch4 := gomonkey.ApplyFunc(orm.NewOrm, func() orm.Ormer {
		// do nothing
		return nil
	})
	defer patch4.Reset()

	patch5 := gomonkey.ApplyFunc(orm.Ormer.Using, func(_ orm.Ormer, _ string) error {
		// do nothing
		return nil
	})
	defer patch5.Reset()

	db := &dbAdapter.PgDb{}
	os.Setenv(LcmControllerDbPwd, LcmControllerPwd)
	err := db.InitDatabase()
	assert.Error(t, err, "TestInitDbSuccess execution result")
}

func TestInitDbFailure1(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDriver, func(_ string, _ orm.DriverType) error {
		// do nothing
		return nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) error {
		// do nothing
		return nil
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) error {
		// do nothing
		return errors.New("Failred to register database")
	})
	defer patch3.Reset()

	patch4 := gomonkey.ApplyFunc(orm.NewOrm, func() orm.Ormer {
		// do nothing
		return nil
	})
	defer patch4.Reset()

	patch5 := gomonkey.ApplyFunc(orm.Ormer.Using, func(_ orm.Ormer, _ string) error {
		// do nothing
		return nil
	})
	defer patch5.Reset()

	db := &dbAdapter.PgDb{}
	os.Setenv(LcmControllerDbPwd, LcmControllerPwd)
	err := db.InitDatabase()
	assert.Error(t, err, "TestInitDbFailure1 execution result")
}

func TestInitDbFailure2(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDriver, func(_ string, _ orm.DriverType) error {
		// do nothing
		return errors.New("failed to register driver")
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) error {
		// do nothing
		return nil
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) error {
		// do nothing
		return errors.New("failed to register database")
	})
	defer patch3.Reset()

	patch4 := gomonkey.ApplyFunc(orm.NewOrm, func() orm.Ormer {
		// do nothing
		return nil
	})
	defer patch4.Reset()

	patch5 := gomonkey.ApplyFunc(orm.Ormer.Using, func(_ orm.Ormer, _ string) error {
		// do nothing
		return nil
	})
	defer patch5.Reset()

	db := &dbAdapter.PgDb{}
	os.Setenv(LcmControllerDbPwd, LcmControllerPwd)
	err := db.InitDatabase()
	assert.Error(t, err, "TestInitDbFailure2 execution result")
}

func TestInitDbFailure3(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDriver, func(_ string, _ orm.DriverType) error {
		// do nothing
		return nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) error {
		// do nothing
		return errors.New("failed to run sync db")
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) error {
		// do nothing
		return nil
	})
	defer patch3.Reset()

	patch4 := gomonkey.ApplyFunc(orm.NewOrm, func() orm.Ormer {
		// do nothing
		return nil
	})
	defer patch4.Reset()

	patch5 := gomonkey.ApplyFunc(orm.Ormer.Using, func(_ orm.Ormer, _ string) error {
		// do nothing
		return nil
	})
	defer patch5.Reset()

	db := &dbAdapter.PgDb{}
	os.Setenv(LcmControllerDbPwd, LcmControllerPwd)
	err := db.InitDatabase()
	assert.Error(t, err, "TestInitDbFailure3 execution result")
}

func TestInitDbFailure4(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDriver, func(_ string, _ orm.DriverType) error {
		// do nothing
		return nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) error {
		// do nothing
		return errors.New("failed to run sync db")
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) error {
		// do nothing
		return nil
	})
	defer patch3.Reset()

	patch4 := gomonkey.ApplyFunc(orm.NewOrm, func() orm.Ormer {
		// do nothing
		return nil
	})
	defer patch4.Reset()

	patch5 := gomonkey.ApplyFunc(orm.Ormer.Using, func(_ orm.Ormer, _ string) error {
		// do nothing
		return nil
	})
	defer patch5.Reset()

	db := &dbAdapter.PgDb{}
	os.Setenv(LcmControllerDbPwd, "abc")
	err := db.InitDatabase()
	assert.Error(t, err, "TestInitDbFailure4 execution result")
}

func TestGetDbAdapterSuccess1(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) (error) {
		// do nothing
		return errors.New("failed to register database")
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) (error) {
		// do nothing
		return nil
	})
	defer patch2.Reset()

	var c *dbAdapter.PgDb
	patch3 := gomonkey.ApplyMethod(reflect.TypeOf(c), "InitOrmer", func(*dbAdapter.PgDb) (error) {
		go func() {
			// do nothing
		}()
		return nil
	})
	defer patch3.Reset()

	os.Setenv(LcmControllerDbPwd, LcmControllerPwd)
	beego.AppConfig.Set("dbAdapter", "pgDb")
	_, err := dbAdapter.GetDbAdapter()
	assert.Error(t, err, "TestGetDbAdapterSuccess1 execution result")
}