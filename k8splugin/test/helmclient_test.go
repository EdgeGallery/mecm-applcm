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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/agiledragon/gomonkey"
	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/release"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/metrics/pkg/apis/metrics/v1beta1"
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
	failedToGetClientSet = "failed to get clientset"
	outputSuccess        = "{\"Output\":\"Success\"}"
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
	assert.Equal(t, "{\"cpuusage\":{\"total\":0,\"used\":0},\"memusage\":{\"total\":0,\"used\":0}}", result, "Test query kpi execution result")
}

func TestGetLabelSelector(t *testing.T) {
	manifestBuf := []adapter.Manifest{}
	manifest := adapter.Manifest{
		APIVersion: "v1",
		Kind: "Deployment",
	}
	manifest.Metadata.Labels.App = "appName"
	manifest.Metadata.Name = "name"
	manifest.Metadata.Namespace ="default"

	manifestBuf = append(manifestBuf, manifest)
	result := adapter.GetLabelSelector(manifestBuf)
	assert.NotEmpty(t, result, "Test get label selector execution result")
}

func TestGetJSONResponse1(t *testing.T) {
	var appInfo models.AppInfo
	patch3 := gomonkey.ApplyFunc(json.Marshal, func(_ interface{}) (b []byte, err error) {
		// do nothing
		return b, errors.New("error")
	})
	defer patch3.Reset()
	m := map[string]string{}
	m["key1"] = "value1"

	_, result := adapter.GetJSONResponse(appInfo, m)
	assert.NotEmpty(t, result, "Test get json response result")

}

func TestGetJSONResponse2(t *testing.T) {
	var appInfo models.AppInfo
	m := map[string]string{}
	m["key1"] = "value1"

	result , _ := adapter.GetJSONResponse(appInfo, m)
	assert.Equal(t, "{\"key1\":\"value1\"}", result, "Test get json response result")
}

func TestGetJSONResponse3(t *testing.T) {
	var appInfo models.AppInfo
	patch3 := gomonkey.ApplyFunc(json.Marshal, func(_ interface{}) (b []byte, err error) {
		// do nothing
		return b, errors.New("error")
	})
	defer patch3.Reset()
	result , _ := adapter.GetJSONResponse(appInfo, nil)
	assert.Equal(t, "", result, "Test get json response result for null response")
}

func TestGetDeploymentArtifact(t *testing.T) {
	patch := gomonkey.ApplyFunc(json.Marshal, func(_ interface{}) (b []byte, err error) {
		// do nothing
		return b, errors.New("error")
	})
	defer patch.Reset()
	_, result := adapter.GetDeploymentArtifact("path", "ext")
	assert.NotEmpty(t, result, "Test get json response result")
}

func TestSplitManifestYaml(t *testing.T) {
	bytes := []byte("manifest")
	_, result := adapter.SplitManifestYaml(bytes)
	assert.NotEmpty(t, result, "Test get label selector execution result")
}


func TestGetClientSet(t *testing.T) {
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
			return &release.Release{}, errors.New("error")
		})
	defer patch4.Reset()

	client, _ := adapter.NewHelmClient(hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	_, _, result  := client.GetClientSet("release", "test")
	assert.NotEmpty(t, result, "Test get client set execution result")
}


func TestGetClientSet1(t *testing.T) {
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
		return kubeconfig, errors.New("error")
	})
	defer patch5.Reset()

	client, _ := adapter.NewHelmClient(hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	_, _, result  := client.GetClientSet("release", "test")
	assert.NotEmpty(t, result, "Test get label selector execution result")
}


func TestGetClientSet2(t *testing.T) {
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
		return cs, errors.New("error")
	})
	defer patch6.Reset()

	client, _ := adapter.NewHelmClient(hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	_, _, result  := client.GetClientSet("release", "test")
	assert.NotEmpty(t, result, "Test get label selector execution result")
}


func TestGetClientSet3(t *testing.T) {
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

	patch5 := gomonkey.ApplyFunc(adapter.SplitManifestYaml, func(data []byte) (manifest []adapter.Manifest, err error) {

		return manifest, errors.New("error")
	})
	defer patch5.Reset()

	client, _ := adapter.NewHelmClient(hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	_, _, result  := client.GetClientSet("release", "test")
	assert.NotEmpty(t, result, "Test get label selector execution result")
}

func TestGetPodInfo(t *testing.T) {

	var pod v1.Pod
	pod.Kind = "Deployment"
	pod.Namespace = "default"
	pod.Name = "pod1"
	pod.APIVersion= "v1"

	podList := &v1.PodList{
		TypeMeta: metav1.TypeMeta{},
		ListMeta: metav1.ListMeta{},
	}
	podList.Items = append(podList.Items, pod)

	patch5 := gomonkey.ApplyFunc(adapter.GetPodMetrics, func(config *rest.Config, podName, namespace string) (podMetrics *v1beta1.PodMetrics, err error) {
		podMetrics = &v1beta1.PodMetrics{Containers: []v1beta1.ContainerMetrics{
		{
			Name: "container1-1",
			Usage: v1.ResourceList{
				v1.ResourceCPU:     *resource.NewMilliQuantity(1, resource.DecimalSI),
				v1.ResourceMemory:  *resource.NewQuantity(2*(1024*1024), resource.DecimalSI),
				v1.ResourceStorage: *resource.NewQuantity(3*(1024*1024), resource.DecimalSI),
			},
		},
	}, }
		return podMetrics, nil
	})
	defer patch5.Reset()

	patch6 := gomonkey.ApplyFunc(adapter.GetTotalCpuDiskMemory, func(clientset *kubernetes.Clientset) (string, string, string, error) {

		return "1", "2", "4", nil
	})
	defer patch6.Reset()

	_, result := adapter.GetPodInfo(podList,nil, nil, "config")
	assert.Nil(t, result, "Test Get Pod Info execution result")
}


func TestGetPodInfo1(t *testing.T) {

	var pod v1.Pod
	pod.Kind = "Deployment"
	pod.Namespace = "default"
	pod.Name = "pod1"
	pod.APIVersion= "v1"

	podList := &v1.PodList{
		TypeMeta: metav1.TypeMeta{},
		ListMeta: metav1.ListMeta{},
	}
	podList.Items = append(podList.Items, pod)

	patch5 := gomonkey.ApplyFunc(adapter.GetPodMetrics, func(config *rest.Config, podName, namespace string) (podMetrics *v1beta1.PodMetrics, err error) {
		podMetrics = &v1beta1.PodMetrics{Containers: []v1beta1.ContainerMetrics{
			{
				Name: "container1-1",
				Usage: v1.ResourceList{
					v1.ResourceCPU:     *resource.NewMilliQuantity(1, resource.DecimalSI),
					v1.ResourceMemory:  *resource.NewQuantity(2*(1024*1024), resource.DecimalSI),
					v1.ResourceStorage: *resource.NewQuantity(3*(1024*1024), resource.DecimalSI),
				},
			},
		}, }
		return podMetrics, errors.New("error")
	})
	defer patch5.Reset()

	patch6 := gomonkey.ApplyFunc(adapter.GetTotalCpuDiskMemory, func(clientset *kubernetes.Clientset) (string, string, string, error) {

		return "1", "2", "4", nil
	})
	defer patch6.Reset()

	_, result := adapter.GetPodInfo(podList,nil, nil, "config")
	assert.Nil(t, result, "Test Get Pod Info execution result")
}


func TestGetPodInfo2(t *testing.T) {

	var pod v1.Pod
	pod.Kind = "Deployment"
	pod.Namespace = "default"
	pod.Name = "pod1"
	pod.APIVersion= "v1"

	podList := &v1.PodList{
		TypeMeta: metav1.TypeMeta{},
		ListMeta: metav1.ListMeta{},
	}
	podList.Items = append(podList.Items, pod)

	patch5 := gomonkey.ApplyFunc(adapter.GetPodMetrics, func(config *rest.Config, podName, namespace string) (podMetrics *v1beta1.PodMetrics, err error) {
		podMetrics = &v1beta1.PodMetrics{Containers: []v1beta1.ContainerMetrics{
			{
				Name: "container1-1",
				Usage: v1.ResourceList{
					v1.ResourceCPU:     *resource.NewMilliQuantity(1, resource.DecimalSI),
					v1.ResourceMemory:  *resource.NewQuantity(2*(1024*1024), resource.DecimalSI),
					v1.ResourceStorage: *resource.NewQuantity(3*(1024*1024), resource.DecimalSI),
				},
			},
		}, }
		return podMetrics, nil
	})
	defer patch5.Reset()

	patch6 := gomonkey.ApplyFunc(adapter.GetTotalCpuDiskMemory, func(clientset *kubernetes.Clientset) (string, string, string, error) {

		return "1", "2", "4", errors.New("error")
	})
	defer patch6.Reset()

	_, result := adapter.GetPodInfo(podList,nil, nil, "config")
	assert.Error(t, result, "Test Get Pod Info execution result")
}

