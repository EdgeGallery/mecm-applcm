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
	tenantId              string      = "e921ce54-82c8-4532-b5c6-8516cf75f7a6"
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

	patch2 := gomonkey.ApplyFunc(adapter.GetClient, func(_ string, tenantId string, _ string) (adapter.ClientIntf, error) {
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
	status, _ := client.UploadPkg(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", hostIpAddress, token, packageId, tenantIdentifier)
	assert.Equal(t, util.Success, status, "Upload Package failed")
	status, _ = client.UploadPkg(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", "256.1.1.1", token, packageId, tenantIdentifier)
	assert.Equal(t, util.Failure, status, "Upload Package failed")
	token1 := "1"
	status, _ = client.UploadPkg(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", hostIpAddress, token1, packageId, tenantIdentifier)
	assert.Equal(t, util.Failure, status, "Upload Package failed")
	status, _ = client.UploadPkg(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", hostIpAddress, token, "", tenantIdentifier)
	assert.Equal(t, util.Failure, status, "Upload Package failed")
	status, _ = client.UploadPkg(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", hostIpAddress, token, packageId, "1")
	assert.Equal(t, util.Failure, status, "Upload Package failed")

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
	status, _ = client.Instantiate(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", "256.1.1.1", token,
		appInstanceIdentifier, ak, sk)
	assert.Equal(t, "", status, "Instantiation failed")
	token1 := "1"
	status, _ = client.Instantiate(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", hostIpAddress, token1,
		appInstanceIdentifier, ak, sk)
	assert.Equal(t, "", status, "Instantiation failed")
	status, _ = client.Instantiate(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", hostIpAddress, token,
		"1", ak, sk)
	assert.Equal(t, "", status, "Instantiation failed")
	ak1 := ""
	status, _ = client.Instantiate(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", hostIpAddress, token,
		appInstanceIdentifier, ak1, sk)
	assert.Equal(t, "", status, "Instantiation failed")
	sk1 := ""
	status, _ = client.Instantiate(dir+"/"+"e17d23de-e562-4c81-b242-0d3926a2255f.csar", hostIpAddress, token,
		appInstanceIdentifier, ak, sk1)
	assert.Equal(t, "", status, "Instantiation failed")

}

func testQuery(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.Query(token, appInstanceIdentifier, hostIpAddress)
	assert.Equal(t, outputSuccess, status, "Query failed")
	status, _ = client.Query(token, appInstanceIdentifier, "256.1.1.1")
	assert.Equal(t, "", status, "Query failed")
	status, _ = client.Query(token, "1.1.1.1", hostIpAddress)
	assert.Equal(t, "", status, "Query failed")
	token1 := "1"
	status, _ = client.Query(token1, "1.1.1.1", hostIpAddress)
	assert.Equal(t, "", status, "Query failed")
}



func testQueryKpiInfo(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.QueryKpiInfo(token, hostIpAddress)
	assert.Equal(t, outputSuccess, status, "Query kpi failed")
	status, _ = client.QueryKpiInfo(token, "256.1.1.1")
	assert.Equal(t, "", status, "Query kpi failed")
	token1 := "1"
	status, _ = client.QueryKpiInfo(token1, hostIpAddress)
	assert.Equal(t, "", status, "Query kpi failed")
}

func testPodDescribe(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.WorkloadEvents(token, appInstanceIdentifier, hostIpAddress)
	assert.Equal(t, outputSuccess, status, "Pod describe failed")
	status, _ = client.WorkloadEvents(token, appInstanceIdentifier, "256.1.1.1")
	assert.Equal(t, "", status, "Pod describe failed")
	status, _ = client.WorkloadEvents(token, "1", hostIpAddress)
	assert.Equal(t, "", status, "Pod describe failed")
	token1 := "1"
	status, _ = client.WorkloadEvents(token1, appInstanceIdentifier, hostIpAddress)
	assert.Equal(t, "", status, "Pod describe failed")
}

func testTerminate(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.Terminate(hostIpAddress, token, appInstanceIdentifier)
	assert.Equal(t, util.Success, status, "Terminate failed")
	status, _ = client.Terminate("256.1.1.1", token, appInstanceIdentifier)
	assert.Equal(t, "", status, "Terminate failed")
	status, _ = client.Terminate(hostIpAddress, token, "1.1.1.1")
	assert.Equal(t, "", status, "Terminate failed")
	token1 := "1"
	status, _ = client.Terminate(hostIpAddress, token1, "1.1.1.1")
	assert.Equal(t, "", status, "Terminate failed")
}

func testUpload(t *testing.T, dir string, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.UploadConfig(dir+"/"+"configFile", hostIpAddress, token)
	assert.Equal(t, util.Success, status, "Upload failed")
	status, _ = client.UploadConfig(dir+"/"+"configFile", "256.1.1.1", token)
	assert.Equal(t, "Failure", status, "Upload failed")
	token1 := "1"
	status, _ = client.UploadConfig(dir+"/"+"configFile", hostIpAddress, token1)
	assert.Equal(t, "Failure", status, "Upload failed")
}

func testRemoval(t *testing.T, config *conf.Configurations) {
	client := &mockGrpcClient{}
	client.dialToServer(config.Server.HttpsAddr + ":" + config.Server.ServerPort)
	status, _ := client.RemoveConfig(hostIpAddress, token)
	assert.Equal(t, util.Success, status, "Remove failed")
	status, _ = client.RemoveConfig("256.1.1.1", token)
	assert.Equal(t, "", status, "Remove failed")
	token1 := "1"
    status, _ = client.RemoveConfig(hostIpAddress, token1)
	assert.Equal(t, "", status, "Remove failed")
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
