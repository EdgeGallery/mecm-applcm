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
	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/release"
	"k8splugin/config"
	"k8splugin/models"
	"k8splugin/pkg/adapter"
	"k8splugin/util"
	"math/rand"
	"os"
	"reflect"
	"testing"
)
    var (
		ipAddFormatter = "%d.%d.%d.%d"
		fwdIp          = fmt.Sprintf(ipAddFormatter, rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal),
			rand.Intn(util.MaxIPVal))

		tenantIdentifier      = "e921ce54-82c8-4532-b5c6-8516cf75f7a6"
		packageId             = "e261211d80d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98"
		appName               = "postioning-service"
		queryFailed           = "Query failed"
    )


func TestDeploySuccess(t *testing.T) {

	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(_ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: "/usr/app/config/" + ipAddress}, nil
	})
	defer patch1.Reset()

	var c *config.AppAuthConfigBuilder
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), "AddValues",
		func(*config.AppAuthConfigBuilder, *os.File) (string, error) {
		go func() {
			// do nothing
		}()
		return "test", nil
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(loader.Load, func(_ string) (*chart.Chart, error) {
		// do nothing
		c := new(chart.Chart)
		c.Metadata = new(chart.Metadata)
		return 	c, nil
	})
	defer patch3.Reset()

	var i *action.Install
	patch4 := gomonkey.ApplyMethod(reflect.TypeOf(i), "Run",
		func(*action.Install, *chart.Chart, map[string]interface{}) (*release.Release, error) {
		go func() {
			// do nothing
		}()
		return &release.Release{}, nil
	})
	defer patch4.Reset()

	// Get client
	client, err := adapter.GetClient("helm", ipAddress)
	if err != nil {
		return
	}

	result, err := client.Deploy(tenantIdentifier, hostIpAddress,  packageId,  appInstanceIdentifier,  ak,  sk,
	&mockK8sPluginDb{appInstanceRecords: make(map[string]models.AppInstanceInfo)})
	assert.Equal(t, "", result, "TestGetReleaseNamespaceSuccess execution result")
}
