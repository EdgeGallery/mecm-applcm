package test

import (
	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego"
	"os"
	"reflect"
	"rescontroller/models"
	"rescontroller/util"
	"testing"
	"time"
)

var (
	k8sPluginAddr     = "127.0.0.1"
	k8sPluginPort     = "10001"
	k8sPluginEndPoint = "127.0.0.1:10001"
)

func TestWithClient(t *testing.T) {

	go startServer()
	time.Sleep(1000 * time.Millisecond)
	doTest(t)
}

func doTest(t *testing.T) {

	// Mock the required API
	patch1 := gomonkey.ApplyFunc(util.GetAppConfig, func(k string) string {
		if k == "client_ssl_enable" {
			return "false"
		}
		if k == "clientProtocol" {
			return "grpc"
		}
		return ""
	})
	defer patch1.Reset()

	var c *beego.Controller
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), "ServeJSON", func(*beego.Controller, ...bool) {
		go func() {
			// do nothing
		}()
	})
	defer patch2.Reset()

	// Set the environment variables for lcmcontroller for k8spluging
	_ = os.Setenv("K8S_PLUGIN", k8sPluginAddr)
	_ = os.Setenv("K8S_PLUGIN_PORT", k8sPluginPort)

	// Common steps
//	baseDir, _ := os.Getwd()
//	path := baseDir + "/positioning_with_mepagent_new.csar"
//	controllers.PackageFolderPath = baseDir + directory
//	_ = os.Mkdir(baseDir+directory, filePermission)
	extraParams := map[string]string{
		"hostIp":  "1.1.1.1",
		"tenantId": tenantIdentifier,
		"appName": "postioning-service",
		"packageId": "e261211d80d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98",
		"appId": "e261211d80d04cb6aed00e5cd1f2cd11",
	}

	testDb := &MockDb{appInstanceRecords: make(map[string]models.AppInfoRecord),
		mecHostRecords: make(map[string]models.MecHost),}

	hostInfoRecord := &models.MecHost{
		MechostIp: ipAddress,
		MechostName: "edgegallery",
		ZipCode: "560048",
		City: "xian",
		Address: "xian",
		Affinity: "shenzhen",
		UserName: "root",
		Coordinates:"1,2",
	}
	testDb.mecHostRecords["1.1.1.1"] = *hostInfoRecord

	testCreateFlavor(t, extraParams, testDb)
	testDeleteFlavor(t, extraParams, testDb)

	testCreateSecurityGroup(t, extraParams, testDb)
	testCreateSecurityGroupRule(t, extraParams, testDb)
	testDeleteSecurityGroupRule(t, extraParams, testDb)
	testDeleteSecurityGroup(t, extraParams, testDb)

	testCreateImage(t, extraParams, testDb)
	testImportImage(t, extraParams, testDb)
	testDeleteImage(t, extraParams, testDb)

	testCreateServer(t, extraParams, testDb)
	testOperateServer(t, extraParams, testDb)
	testDeleteServer(t, extraParams, testDb)
	testDeleteServer1(t, extraParams, testDb)
	testDeleteServer2(t, extraParams, testDb)

	testCreateNetwork(t, extraParams, testDb)
	testDeleteNetwork(t, extraParams, testDb)
}

func startServer() {
	// Start GRPC Server
	grpcServer := &ServerGRPC{Address: k8sPluginEndPoint}
	// Start listening
	_ = grpcServer.Listen()
}

