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

package test

import (
	"errors"
	"fmt"
	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego/orm"
	"github.com/stretchr/testify/assert"
	"k8splugin/pgdb"
	"k8splugin/pkg/adapter"
	"k8splugin/pkg/server"
	"k8splugin/util"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

var (
	ipAddress = fmt.Sprintf("%d.%d.%d.%d", rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal),
		rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal))
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

	var c *pgdb.PgDb
	patch3 := gomonkey.ApplyMethod(reflect.TypeOf(c), "InitOrmer", func(*pgdb.PgDb) (error) {
		go func() {
			// do nothing
		}()
		return nil
	})
	defer patch3.Reset()

	dir, _ := os.Getwd()
	config, err := util.GetConfiguration(dir)
	if err != nil {
		return
	}

	os.Setenv("K8S_PLUGIN_DB_PASSWORD", "fe0Hmv%sbq")

	// Create GRPC server
	serverConfig := server.ServerGRPCConfig{Address: config.Server.HttpsAddr, Port: config.Server.ServerPort,
		ServerConfig: &config.Server}
	_, err = pgdb.GetDbAdapter(serverConfig.ServerConfig)
	assert.NoError(t, err, "TestGetDbAdapterSuccess execution result")
	serverConfig.ServerConfig.DbAdapter = "default"
	_, err = pgdb.GetDbAdapter(serverConfig.ServerConfig)
	assert.Error(t, err, "TestGetDbAdapterSuccess execution result")
}

func TestGetGetClientSuccess(t *testing.T) {
	_, err := adapter.GetClient(util.DeployType, ipAddress)
	assert.Error(t, err, "TestGetGetClientSuccess execution result")
	_, err = adapter.GetClient("default", ipAddress)
	assert.Error(t, err, "TestGetGetClientSuccess execution result")
}

func TestInitDbFailure(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) error {
		// do nothing
		return errors.New("failed to register driver")
	})
	defer patch1.Reset()
	db := &pgdb.PgDb{}
	dir, _ := os.Getwd()
	os.Setenv("K8S_PLUGIN_DB_PASSWORD", "simple")
	config, err := util.GetConfiguration(dir)
	err = db.InitDatabase(&config.Server)
	assert.Error(t, err, "TestGetGetClientFailure execution result")

	os.Setenv("K8S_PLUGIN_DB_PASSWORD", "fe0Hmv%sbq")
	err = db.InitDatabase(&config.Server)
	assert.Error(t, err, "TestGetGetClientFailure execution result")
}

func TestInitDbFailure1(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) error {
		// do nothing
		return nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) error {
		// do nothing
		return errors.New("failed to run sync database")
	})
	defer patch2.Reset()
	db := &pgdb.PgDb{}
	dir, _ := os.Getwd()
	config, err := util.GetConfiguration(dir)
	config.Server.DbAdapter = "default"
	os.Setenv("K8S_PLUGIN_DB_PASSWORD", "fe0Hmv%sbq")
	err = db.InitDatabase(&config.Server)
	assert.Error(t, err, "TestGetGetClientFailure execution result")
}

func TestInitDbFailure2(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) error {
		// do nothing
		return nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) error {
		// do nothing
		return nil
	})
	defer patch2.Reset()
	var c *pgdb.PgDb
	patch3 := gomonkey.ApplyMethod(reflect.TypeOf(c), "InitOrmer", func(*pgdb.PgDb) (error) {
		go func() {
			// do nothing
		}()
		return errors.New("failed to init ormer")
	})
	defer patch3.Reset()

	db := &pgdb.PgDb{}
	dir, _ := os.Getwd()
	config, err := util.GetConfiguration(dir)
	config.Server.DbAdapter = "default"
	os.Setenv("K8S_PLUGIN_DB_PASSWORD", "fe0Hmv%sbq")
	err = db.InitDatabase(&config.Server)
	assert.Error(t, err, "TestGetGetClientFailure execution result")
}

func TestInitDbFailure3(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDriver, func(driverName string, typ orm.DriverType) error {
		// do nothing
		return errors.New("Failed to register database")
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) error {
		// do nothing
		return nil
	})
	defer patch2.Reset()
	var c *pgdb.PgDb
	patch3 := gomonkey.ApplyMethod(reflect.TypeOf(c), "InitOrmer", func(*pgdb.PgDb) (error) {
		go func() {
			// do nothing
		}()
		return errors.New("failed to init ormer")
	})
	defer patch3.Reset()

	db := &pgdb.PgDb{}
	dir, _ := os.Getwd()
	config, err := util.GetConfiguration(dir)
	config.Server.DbAdapter = "default"
	os.Setenv("K8S_PLUGIN_DB_PASSWORD", "fe0Hmv%sbq")
	err = db.InitDatabase(&config.Server)
	assert.Error(t, err, "TestGetGetClientFailure execution result")
}


func TestInitDbFailure4(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDriver, func(driverName string, typ orm.DriverType) error {
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

	patch5 := gomonkey.ApplyFunc(orm.Ormer.Using, func(ormer orm.Ormer, str string) error {
		// do nothing
		return nil
	})
	defer patch5.Reset()

	db := &pgdb.PgDb{}
	dir, _ := os.Getwd()
	config, err := util.GetConfiguration(dir)
	config.Server.DbAdapter = "default"
	os.Setenv("K8S_PLUGIN_DB_PASSWORD", "fe0Hmv%sbq")
	err = db.InitDatabase(&config.Server)
	assert.Error(t, err, "TestGetGetClientFailure execution result")
}
