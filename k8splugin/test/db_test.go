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
	ipAddress = fmt.Sprintf(util.IpAddFormatter, rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal),
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
	serverConfig := server.ServerGRPCConfig{Address: config.Server.Httpsaddr, Port: config.Server.Serverport,
		ServerConfig: &config.Server}
	_, err = pgdb.GetDbAdapter(serverConfig.ServerConfig)
	assert.NoError(t, err, "TestGetDbAdapterSuccess execution result")
	serverConfig.ServerConfig.DbAdapter = "default"
	_, err = pgdb.GetDbAdapter(serverConfig.ServerConfig)
	assert.Error(t, err, "TestGetDbAdapterSuccess execution result")
}

func TestGetGetClientSuccess(t *testing.T) {
	_, err := adapter.GetClient("helm", ipAddress)
	assert.Error(t, err, "TestGetGetClientSuccess execution result")
	_, err = adapter.GetClient("default", ipAddress)
	assert.Error(t, err, "TestGetGetClientSuccess execution result")
}



