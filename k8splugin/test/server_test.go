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
	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"k8splugin/conf"
	"k8splugin/models"
	"k8splugin/pgdb"
	"k8splugin/pkg/adapter"
	"k8splugin/pkg/server"
	"k8splugin/util"
	"os"
	"testing"
	"time"
)

var (
	hostIpAddress         string      = ipAddress
	filePermission        os.FileMode = 0750
	directory             string      = "/config/"
	appInstanceIdentifier string      = "e921ce54-82c8-4532-b5c6-8516cf75f7a4"
	ak                    string      = "aQqizVqpGLWLaqKJZgU="
	sk                    string      = "d0mutLOkfj1/vTQZY9s679lnp6199wqR9d5FVg=="
	token                 string      = createToken(1)
)

func TestServer(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(pgdb.GetDbAdapter, func(_ *conf.ServerConfigurations) (pgdb.Database, error) {
		return &mockK8sPluginDb{appInstanceRecords: make(map[string]models.AppInstanceInfo)}, nil
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
	testQuery(t, config)
	testTerminate(t, config)

	// Pre steps
	baseDir, _ := os.Getwd()
	server.KubeconfigPath = baseDir + directory
	_ = os.Mkdir(baseDir+directory, filePermission)

	testUpload(t, dir, config)
	testRemoval(t, config)

	// Cleanup
	_ = os.RemoveAll(baseDir + directory)
}

func testInstantiate(t *testing.T, dir string, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.Httpsaddr + ":" + config.Server.Serverport)
	status, _ := client.Instantiate(dir+"/"+"7e9b913f-748a-42b7-a088-abe3f750f04c.tgz", hostIpAddress, token,
		appInstanceIdentifier, ak, sk)
	assert.Equal(t, util.Success, status, "Instantiation failed")
}

func testQuery(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.Httpsaddr + ":" + config.Server.Serverport)
	status, _ := client.Query(token, appInstanceIdentifier, hostIpAddress)
	assert.Equal(t, "{\"Output\":\"Success\"}", status, "Query failed")
}

func testTerminate(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.Httpsaddr + ":" + config.Server.Serverport)
	status, _ := client.Terminate(hostIpAddress, token, appInstanceIdentifier)
	assert.Equal(t, util.Success, status, "Terminate failed")
}

func testUpload(t *testing.T, dir string, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.Httpsaddr + ":" + config.Server.Serverport)
	status, _ := client.UploadConfig(dir+"/"+"7e9b913f-748a-42b7-a088-abe3f750f04c.tgz", hostIpAddress, token)
	assert.Equal(t, util.Success, status, "Upload failed")
}

func testRemoval(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.Httpsaddr + ":" + config.Server.Serverport)
	status, _ := client.RemoveConfig(hostIpAddress, token)
	assert.Equal(t, util.Success, status, "Upload failed")
}

func startServer(server server.ServerGRPC) {
	err := server.Listen()
	if err != nil {
		log.Errorf("Exiting system...")
		return
	}
}

func createToken(userid uint64) string {
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	roleName := make([]string, 3)
	roleName[0] = "ROLE_MECM_TENANT"
	roleName[1] = "ROLE_APPSTORE_TENANT"
	roleName[2] = "ROLE_DEVELOPER_TENANT"
	atClaims["authorities"] = roleName
	atClaims["user_name"] = "lcmcontroller"
	atClaims["authorized"] = true
	atClaims["userId"] = userid
	atClaims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, _ := at.SignedString([]byte("jdnfksdmfksd"))
	return token
}
