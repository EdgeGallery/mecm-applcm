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
	"bytes"
	"github.com/agiledragon/gomonkey"
	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/release"
	"k8splugin/config"
	"k8splugin/pkg/adapter"
	"os"
	"reflect"
	"testing"
)

func TestDeploySuccess(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(_ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: "192.168.1.1", Kubeconfig: "/usr/app/config/192.168.1.1"}, nil
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
	client, err := adapter.GetClient("helm", "192.168.1.1")
	if err != nil {
		return
	}
	pkg := bytes.Buffer{}
	result, err := client.Deploy(pkg, "69d01999-dc53-4f59-a7f4-229b254340c2",
	"OzXpsJXuuNuyz301Hfc=", "DyaLraRyrNvSIIMaoQngvzHvQLkps8TXTCDq29FF1tW3hWtW+S1QDjVHAvlE70h/")
	assert.Equal(t, "", result, "TestGetReleaseNamespaceSuccess execution result")
}
