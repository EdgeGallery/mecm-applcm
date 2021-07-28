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
	token                 string      = createToken("1", "ROLE_MECM_ADMIN", true, true)
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
	serverConfig := server.ServerGRPCConfig{Address: config.Server.HttpsAddr, Port: config.Server.ServerPort,
		ServerConfig: &config.Server}
	grpcServer := server.NewServerGRPC(serverConfig)
	go startServer(grpcServer)
	time.Sleep(1000 * time.Millisecond)
	// Pre steps
	baseDir, _ := os.Getwd()
	server.KubeconfigPath = baseDir + directory
	_ = os.Mkdir(baseDir+directory, filePermission)

	testUpload(t, dir, config)

	testUploadPkg(t, dir, config)
	testDeploySuccess(t)
	testDeployFailure(t)
	testWorkloadEvents(t)
	testQueryInfo(t)
	testQueryKpi(t)
	testUnDeploySuccess(t)
	testDeletePkg(t, config)
	testInstantiate(t, dir, config)
	testQuery(t, config)
	testQueryKpiInfo(t, config)
	testPodDescribe(t, config)
	testTerminate(t, config)


	testRemoval(t, config)

	// Cleanup
	_ = os.RemoveAll(baseDir + directory)
}

func testUploadPkg(t *testing.T, dir string, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.UploadPkg(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", hostIpAddress, token)
	assert.Equal(t, util.Success, status, "Upload Package failed")
}

func testDeletePkg(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.DeletePkg()
	assert.Equal(t, util.Success, status, "Instantiation failed")
}

func testInstantiate(t *testing.T, dir string, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.Instantiate(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", hostIpAddress, token,
		appInstanceIdentifier, ak, sk)
	assert.Equal(t, util.Success, status, "Instantiation failed")
}

func testQuery(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.Query(token, appInstanceIdentifier, hostIpAddress)
	assert.Equal(t, outputSuccess, status, "Query failed")
}

func testQueryKpiInfo(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.QueryKpiInfo(token, hostIpAddress)
	assert.Equal(t, outputSuccess, status, "Query failed")
}

func testPodDescribe(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.WorkloadEvents(token, appInstanceIdentifier, hostIpAddress)
	assert.Equal(t, outputSuccess, status, "Pod describe failed")
}

func testTerminate(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.Terminate(hostIpAddress, token, appInstanceIdentifier)
	assert.Equal(t, util.Success, status, "Terminate failed")
}

func testUpload(t *testing.T, dir string, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.UploadConfig(dir+"/"+"configFile", hostIpAddress, token)
	assert.Equal(t, util.Success, status, "Upload failed")
}

func testRemoval(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
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

func createToken(userid string, role string, isRole bool, isUserId bool) string {
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	roleName := make([]string, 3)
	if isRole {
		roleName[0] = role
		roleName[1] = "ROLE_APPSTORE_TENANT"
		roleName[2] = "ROLE_DEVELOPER_TENANT"
	} else {
		roleName = nil
	}
	atClaims["authorities"] = roleName
	if isUserId {
		atClaims["user_name"] = "lcmcontroller"
	} else {
		atClaims["user_name"] = nil
	}
	atClaims["authorized"] = true
	if userid != "" {
		atClaims["userId"] = userid
	} else {
		atClaims["userId"] = nil
	}
	atClaims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, _ := at.SignedString([]byte("jdnfksdmfksd"))
	return token
}
