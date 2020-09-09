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
	"github.com/agiledragon/gomonkey"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"k8splugin/conf"
	"k8splugin/pgdb"
	"k8splugin/pkg/adapter"
	"k8splugin/pkg/server"
	"k8splugin/util"
	"os"
	"testing"
	"time"
)

var (
	hostIpAddress         = "1.1.1.1"
	appInstanceIdentifier = "e921ce54-82c8-4532-b5c6-8516cf75f7a4"
	token                 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGMtODE3OC" +
		"1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZXhwIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2N" +
		"EEwMEFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid2Vuc29uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdi" +
		"NjliIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BUFBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEV" +
		"OQU5UIl0sImp0aSI6IjQ5ZTBhMGMwLTIxZmItNDAwZC04M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibG" +
		"VTbXMiOiJ0cnVlIn0.kmJbwyAxPj7OKpP-5r-WMVKbETpKV0kWMguMNaiNt63EhgrmfDgjmX7eqfagMYBS1sgIKZjuxFg2o-HUaO4h9iE1c" +
		"Lkmm0-8qV7HUSkMQThXGtUk2xljB6K9RxxZzzQNQFpgBB7gEcGVc_t_86tLxUU6FxXEW1h-zW4z4I_oGM9TOg7JR-ZyC8lQZTBNiYaOFHpv" +
		"EubeqfQL0AFIKHeEf18Jm-Xjjw4Y3QEzB1qDMrOGh-55y8kelW1w_Vwbaz45n5-U0DirDpCaa4ergleQIVF6exdjMWKtANGYU6zy48u7EYP" +
		"YsykkDoIOxWYNqWSe557rNvY_3m1Ynam1QJCYUA"
)

func TestServer(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(pgdb.GetDbAdapter, func(_ string) (pgdb.Database, error) {
		return &mockK8sPluginDb{}, nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(adapter.GetClient, func(_ string, _ string) (adapter.ClientIntf, error) {
		// do something
		return &mockedHelmClient{}, nil
	})
	defer patch2.Reset()

	// Common steps
	dir, _ := os.Getwd()
	//configPath :=  dir + "/testConfig.yaml"

	config, err := util.GetConfiguration(dir)
	if err != nil {
		log.Errorf("Exiting system...")
		return
	}

	// Create GRPC server
	serverConfig := server.ServerGRPCConfig{Address: config.Server.Httpsaddr, Port: config.Server.Serverport,
		ServerConfig: &config.Server}
	grpcServer := server.NewServerGRPC(serverConfig)
	go startServer(grpcServer)
	time.Sleep(1000 * time.Millisecond)
	testInstantiate(t, dir, config)
}

func testInstantiate(t *testing.T, dir string, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.Httpsaddr + ":" + config.Server.Serverport)
	status, _ := client.Instantiate(dir+"/"+"7e9b913f-748a-42b7-a088-abe3f750f04c.tgz", hostIpAddress, token,
		appInstanceIdentifier)
	assert.Equal(t, "Success", status, "Instantiation failed")
}

func startServer(server server.ServerGRPC) {
	err := server.Listen()
	if err != nil {
		log.Errorf("Exiting system...")
		return
	}
}
