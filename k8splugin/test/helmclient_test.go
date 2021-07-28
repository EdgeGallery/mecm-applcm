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
	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/release"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8splugin/config"
	"k8splugin/models"
	"k8splugin/pkg/adapter"
	"k8splugin/util"
	"math/rand"
	"net/url"
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
	relName               = "example"
	addValues             = "AddValues"
	configFile            = "/usr/app/artificats/config/"
	namespace             = "default"
	failedToGetClientSet  = "failed to get clientset"
	outputSuccess         = "{\"Output\":\"Success\"}"
)

func testDeploySuccess(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(_ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + ipAddress}, nil
	})
	defer patch1.Reset()

	var c *config.AppAuthConfigBuilder
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), addValues,
		func(*config.AppAuthConfigBuilder, *os.File) (string, string, error) {
		go func() {
			// do nothing
		}()
		return "test", namespace, nil
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(loader.Load, func(_ string) (*chart.Chart, error) {
		// do nothing
		c := new(chart.Chart)
		c.Metadata = new(chart.Metadata)
		return 	c, nil
	})
	defer patch3.Reset()


	patch5 := gomonkey.ApplyFunc(clientcmd.BuildConfigFromFlags, func(_ string, _ string) (*restclient.Config, error) {
		// do nothing

		kubeconfig, _ := restclient.InClusterConfig()
		return kubeconfig, nil
	})
	defer patch5.Reset()

	patch6 := gomonkey.ApplyFunc(kubernetes.NewForConfig, func(*restclient.Config) (*kubernetes.Clientset, error) {
		// do nothing

		var cs *kubernetes.Clientset
		return cs, errors.New(failedToGetClientSet)
	})
	defer patch6.Reset()

	var i *action.Install
	patch4 := gomonkey.ApplyMethod(reflect.TypeOf(i), "Run",
		func(*action.Install, *chart.Chart, map[string]interface{}) (*release.Release, error) {
		go func() {
			// do nothing
		}()
		return &release.Release{}, nil
	})
	defer patch4.Reset()

	client, _ := adapter.NewHelmClient(hostIpAddress)
	appPkgRecord := &models.AppPackage{
		TenantId: tenantIdentifier,
		HostIp: hostIpAddress,
		PackageId: packageId,
	}
	result, _, _ := client.Deploy(appPkgRecord,  appInstanceIdentifier,  ak,  sk,
		&mockK8sPluginDb{appInstanceRecords: make(map[string]models.AppInstanceInfo)})
	assert.Equal(t, "", result, "TestGetReleaseNamespaceSuccess execution result")
}


func testDeployFailure(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(_ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + ipAddress}, nil
	})
	defer patch1.Reset()

	var c *config.AppAuthConfigBuilder
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), addValues,
		func(*config.AppAuthConfigBuilder, *os.File) (string, string, error) {
			go func() {
				// do nothing
			}()
			return "test", namespace, nil
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
			return &release.Release{}, errors.New("Deploy failed")
		})
	defer patch4.Reset()

	client, _ := adapter.NewHelmClient(hostIpAddress)
	appPkgRec := &models.AppPackage{
		TenantId: tenantIdentifier,
		HostIp: hostIpAddress,
		PackageId: packageId,
	}
	result, _, _ := client.Deploy(appPkgRec,  appInstanceIdentifier,  ak,  sk,
		&mockK8sPluginDb{appInstanceRecords: make(map[string]models.AppInstanceInfo)})
	assert.Equal(t, "", result, "TestGetReleaseNamespaceSuccess execution result")
}

func testUnDeploySuccess(t *testing.T) {

	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(_ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + ipAddress}, nil
	})
	defer patch1.Reset()

	var c *config.AppAuthConfigBuilder
	patch2 := gomonkey.ApplyMethod(reflect.TypeOf(c), addValues,
		func(*config.AppAuthConfigBuilder, *os.File) (string, string, error) {
			go func() {
				// do nothing
			}()
			return "test", namespace, nil
		})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(loader.Load, func(_ string) (*chart.Chart, error) {
		// do nothing
		c := new(chart.Chart)
		c.Metadata = new(chart.Metadata)
		return 	c, nil
	})
	defer patch3.Reset()

	var i *action.Uninstall
	patch4 := gomonkey.ApplyMethod(reflect.TypeOf(i), "Run",
		func(*action.Uninstall, string) (*release.UninstallReleaseResponse, error) {
			go func() {
				// do nothing
			}()
			return &release.UninstallReleaseResponse{}, nil
		})
	defer patch4.Reset()

	client, _ := adapter.NewHelmClient(hostIpAddress)

	patch5 := gomonkey.ApplyFunc(clientcmd.BuildConfigFromFlags, func(_ string, _ string) (*restclient.Config, error) {
		// do nothing

		kubeconfig, _ := restclient.InClusterConfig()
		return kubeconfig, nil
	})
	defer patch5.Reset()

	patch6 := gomonkey.ApplyFunc(kubernetes.NewForConfig, func(*restclient.Config) (*kubernetes.Clientset, error) {
		// do nothing

		var cs *kubernetes.Clientset
		return cs, errors.New(failedToGetClientSet)
	})
	defer patch6.Reset()


	result := client.UnDeploy(relName, "test")
	assert.Equal(t, result.Error(), failedToGetClientSet, "TestUnDeploySuccess execution result")
}

func testWorkloadEvents(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(_ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + ipAddress}, nil
	})
	defer patch1.Reset()

	var i *action.Status
	patch4 := gomonkey.ApplyMethod(reflect.TypeOf(i), "Run",
		func(*action.Status, string) (*release.Release, error) {
			go func() {
				// do nothing
			}()
			return &release.Release{}, nil
		})
	defer patch4.Reset()

	patch5 := gomonkey.ApplyFunc(clientcmd.BuildConfigFromFlags, func(_ string, _ string) (*restclient.Config, error) {
		// do nothing

		kubeconfig, _ := restclient.InClusterConfig()
		return kubeconfig, nil
	})
	defer patch5.Reset()

	patch6 := gomonkey.ApplyFunc(kubernetes.NewForConfig, func(*restclient.Config) (*kubernetes.Clientset, error) {
		// do nothing

		var cs *kubernetes.Clientset
		return cs, nil
	})
	defer patch6.Reset()

	client, _ := adapter.NewHelmClient(hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	result, _ := client.WorkloadEvents(relName, namespace)
	assert.Equal(t, "{\"pods\":null}", result, "Test workload events execution result")
}

func testQueryInfo(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(_ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + ipAddress}, nil
	})
	defer patch1.Reset()

	var i *action.Status
	patch4 := gomonkey.ApplyMethod(reflect.TypeOf(i), "Run",
		func(*action.Status, string) (*release.Release, error) {
			go func() {
				// do nothing
			}()
			return &release.Release{}, nil
		})
	defer patch4.Reset()

	patch5 := gomonkey.ApplyFunc(clientcmd.BuildConfigFromFlags, func(_ string, _ string) (*restclient.Config, error) {
		// do nothing

		kubeconfig, _ := restclient.InClusterConfig()
		return kubeconfig, nil
	})
	defer patch5.Reset()

	patch6 := gomonkey.ApplyFunc(kubernetes.NewForConfig, func(*restclient.Config) (*kubernetes.Clientset, error) {
		// do nothing

		var cs *kubernetes.Clientset
		return cs, nil
	})
	defer patch6.Reset()

	client, _ := adapter.NewHelmClient(hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	result, _ := client.Query(relName, namespace)
	assert.Equal(t, "{\"pods\":null,\"services\":null}", result, "Test query info execution result")
}

func testQueryKpi(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(_ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + ipAddress}, nil
	})
	defer patch1.Reset()

	var i *action.Status
	patch4 := gomonkey.ApplyMethod(reflect.TypeOf(i), "Run",
		func(*action.Status, string) (*release.Release, error) {
			go func() {
				// do nothing
			}()
			return &release.Release{}, nil
		})
	defer patch4.Reset()

	patch5 := gomonkey.ApplyFunc(clientcmd.BuildConfigFromFlags, func(_ string, _ string) (*restclient.Config, error) {
		// do nothing

		kubeconfig, _ := restclient.InClusterConfig()
		return kubeconfig, nil
	})
	defer patch5.Reset()


	client, _ := adapter.NewHelmClient(hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	patch6 := gomonkey.ApplyFunc(kubernetes.NewForConfig, func(*restclient.Config) (*kubernetes.Clientset, error) {
		// do nothing
		var cs kubernetes.Clientset

		var clientConfig restclient.ClientContentConfig
		url1, _ := url.Parse("http://bing.com/search?q=dotnet")
		restIntf, _ := restclient.NewRESTClient(url1, "", clientConfig, nil, nil)

		cs.DiscoveryClient = discovery.NewDiscoveryClient(restIntf)
		return &cs, nil

	})
	defer patch6.Reset()

	result, _ := client.QueryKPI()
	assert.Equal(t, "", result, "Test query kpi execution result")
}
