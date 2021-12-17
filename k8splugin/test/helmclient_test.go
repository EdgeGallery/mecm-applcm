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
	"net"
	"net/url"
	"os"
	"reflect"
	"testing"
)

var (
	ipAddFormatter = "%d.%d.%d.%d"
	fwdIp          = fmt.Sprintf(ipAddFormatter, rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal),
		rand.Intn(util.MaxIPVal))

	tenantIdentifier     = "e921ce54-82c8-4532-b5c6-8516cf75f7a6"
	packageId            = "e261211d80d04cb6aed00e5cd1f2cd11b5a6ca9b8f85477bba2cd66fd79d5f98"
	relName              = "example"
	addValues            = "AddValues"
	configFile           = "/usr/app/artificats/config/"
	namespace            = "default"
	failedToGetClientSet = "failed to get clientset"
	outputSuccess        = "{\"Output\":\"Success\"}"
	getClientSet         = "GetClientSet"
	https                = "https://"
)

func testDeploySuccess(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
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
		return c, nil
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

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	appPkgRecord := &models.AppPackage{
		TenantId:  tenantIdentifier,
		HostIp:    hostIpAddress,
		PackageId: packageId,
	}
	result, _, _ := client.Deploy(appPkgRecord, appInstanceIdentifier, ak, sk,
		&mockK8sPluginDb{appInstanceRecords: make(map[string]models.AppInstanceInfo)})
	assert.Equal(t, "", result, "TestGetReleaseNamespaceSuccess execution result")
}

func testDeployFailure(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
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
		return c, nil
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

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	appPkgRec := &models.AppPackage{
		TenantId:  tenantIdentifier,
		HostIp:    hostIpAddress,
		PackageId: packageId,
	}
	result, _, _ := client.Deploy(appPkgRec, appInstanceIdentifier, ak, sk,
		&mockK8sPluginDb{appInstanceRecords: make(map[string]models.AppInstanceInfo)})
	assert.Equal(t, "", result, "TestGetReleaseNamespaceSuccess execution result")
}

func testUnDeploySuccess(t *testing.T) {

	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
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
		return c, nil
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

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)

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
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
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

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	result, _ := client.WorkloadEvents(relName, namespace)
	assert.Equal(t, "{\"pods\":null}", result, "Test work load events execution result")
}

func testQueryInfo(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
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

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	result, _ := client.Query(relName, namespace)
	assert.Equal(t, "{\"pods\":null,\"services\":null,\"cpupercent\":0,\"mempercent\":0}", result, "Test query info execution result")
}

func testQueryKpi(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
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

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
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
	assert.Equal(t, "{\"data\":{\"cpuusage\":{\"total\":0,\"used\":0},\"memusage\":{\"total\":0,\"used\":0}},\"retCode\":0,\"message\":\"success\",\"params\":null}", result, "Test query kpi execution result")
}

func TestGetLabelSelector(t *testing.T) {
	manifestBuf := []adapter.Manifest{}
	manifest := adapter.Manifest{
		APIVersion: "v1",
		Kind:       util.Deployment,
	}
	manifest.Metadata.Labels.App = "appName1"
	manifest.Metadata.Name = "name"
	manifest.Metadata.Namespace = namespace

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

	result, _ := adapter.GetJSONResponse(appInfo, m)
	assert.Equal(t, "{\"key1\":\"value1\"}", result, "Test get json response2 result")
}

func TestGetJSONResponse3(t *testing.T) {
	var appInfo models.AppInfo
	patch3 := gomonkey.ApplyFunc(json.Marshal, func(_ interface{}) (b []byte, err error) {
		// do nothing
		return b, errors.New("error")
	})
	defer patch3.Reset()
	result, _ := adapter.GetJSONResponse(appInfo, nil)
	assert.Equal(t, "", result, "Test get json response result for null response")
}

func TestGetDeploymentArtifact(t *testing.T) {
	patch := gomonkey.ApplyFunc(json.Marshal, func(_ interface{}) (b []byte, err error) {
		// do nothing
		return b, errors.New("error")
	})
	defer patch.Reset()
	_, result := adapter.GetDeploymentArtifact("path", "ext")
	assert.NotEmpty(t, result, "Test Get Deployment Artifact response result")
}

func TestSplitManifestYaml(t *testing.T) {
	bytes := []byte("manifest")
	_, result := adapter.SplitManifestYaml(bytes)
	assert.NotEmpty(t, result, "Test Split ManifestYaml execution result")
}

func TestGetClientSet(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
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

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + tenantId + "/" + hostIpAddress
	_, _, result := client.GetClientSet("release", "test")
	assert.NotEmpty(t, result, "Test get client set execution result")
}

func TestGetClientSet1(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
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

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	_, _, result := client.GetClientSet("release1", "test")
	assert.NotEmpty(t, result, "Test get client set execution result")
}

func TestGetClientSet2(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
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

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	_, _, result := client.GetClientSet("release2", "test")
	assert.NotEmpty(t, result, "Test get client set2 execution result")
}

func TestGetClientSet3(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
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

	patch5 := gomonkey.ApplyFunc(adapter.SplitManifestYaml, func(_ []byte) (manifest []adapter.Manifest, err error) {

		return manifest, errors.New("error")
	})
	defer patch5.Reset()

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	_, _, result := client.GetClientSet("release3", "test")
	assert.NotEmpty(t, result, "Test get client set3 execution result")
}

func TestGetPodInfo(t *testing.T) {

	var pod v1.Pod
	pod.Kind = util.Deployment
	pod.Namespace = namespace
	pod.Name = "pod1"
	pod.APIVersion = "v1"

	podList := &v1.PodList{
		TypeMeta: metav1.TypeMeta{},
		ListMeta: metav1.ListMeta{},
	}
	podList.Items = append(podList.Items, pod)

	patch5 := gomonkey.ApplyFunc(adapter.GetPodMetrics, func(_ *rest.Config, _, _ string) (podMetrics *v1beta1.PodMetrics, err error) {
		podMetrics = &v1beta1.PodMetrics{Containers: []v1beta1.ContainerMetrics{
			{
				Name: "container1-1",
				Usage: v1.ResourceList{
					v1.ResourceCPU:     *resource.NewMilliQuantity(1, resource.DecimalSI),
					v1.ResourceMemory:  *resource.NewQuantity(2*(1024*1024), resource.DecimalSI),
					v1.ResourceStorage: *resource.NewQuantity(3*(1024*1024), resource.DecimalSI),
				},
			},
		}}
		return podMetrics, nil
	})
	defer patch5.Reset()

	patch6 := gomonkey.ApplyFunc(adapter.GetTotalCpuDiskMemory, func(_ *kubernetes.Clientset) (string, string, string, error) {

		return "1", "2", "4", nil
	})
	defer patch6.Reset()

	_, result := adapter.GetPodInfo(podList, nil, nil, "config")
	assert.Nil(t, result, "Test Get Pod Info execution result")
}

func TestGetPodInfo1(t *testing.T) {

	var pod v1.Pod
	pod.Kind = util.Deployment
	pod.Namespace = namespace
	pod.Name = "pod1"
	pod.APIVersion = "v1"

	podList := &v1.PodList{
		TypeMeta: metav1.TypeMeta{},
		ListMeta: metav1.ListMeta{},
	}
	podList.Items = append(podList.Items, pod)

	patch5 := gomonkey.ApplyFunc(adapter.GetPodMetrics, func(_ *rest.Config, _, _ string) (podMetrics *v1beta1.PodMetrics, err error) {
		podMetrics = &v1beta1.PodMetrics{Containers: []v1beta1.ContainerMetrics{
			{
				Name: "container1-2",
				Usage: v1.ResourceList{
					v1.ResourceCPU:     *resource.NewMilliQuantity(1, resource.DecimalSI),
					v1.ResourceMemory:  *resource.NewQuantity(2*(1024*1024), resource.DecimalSI),
					v1.ResourceStorage: *resource.NewQuantity(3*(1024*1024), resource.DecimalSI),
				},
			},
		}}
		return podMetrics, errors.New("error")
	})
	defer patch5.Reset()

	patch6 := gomonkey.ApplyFunc(adapter.GetTotalCpuDiskMemory, func(_ *kubernetes.Clientset) (string, string, string, error) {

		return "1", "2", "4", nil
	})
	defer patch6.Reset()

	_, result := adapter.GetPodInfo(podList, nil, nil, "test")
	assert.Nil(t, result, "Test Get Pod Info1 execution result")
}

func TestGetPodInfo2(t *testing.T) {

	var pod v1.Pod
	pod.Kind = util.Deployment
	pod.Namespace = namespace
	pod.Name = "pod1"
	pod.APIVersion = "v1"

	podList := &v1.PodList{
		TypeMeta: metav1.TypeMeta{},
		ListMeta: metav1.ListMeta{},
	}
	podList.Items = append(podList.Items, pod)

	patch5 := gomonkey.ApplyFunc(adapter.GetPodMetrics, func(_ *rest.Config, _, _ string) (podMetrics *v1beta1.PodMetrics, err error) {
		podMetrics = &v1beta1.PodMetrics{Containers: []v1beta1.ContainerMetrics{
			{
				Name: "container1-3",
				Usage: v1.ResourceList{
					v1.ResourceCPU:     *resource.NewMilliQuantity(1, resource.DecimalSI),
					v1.ResourceMemory:  *resource.NewQuantity(2*(1024*1024), resource.DecimalSI),
					v1.ResourceStorage: *resource.NewQuantity(3*(1024*1024), resource.DecimalSI),
				},
			},
		}}
		return podMetrics, nil
	})
	defer patch5.Reset()

	patch6 := gomonkey.ApplyFunc(adapter.GetTotalCpuDiskMemory, func(_ *kubernetes.Clientset) (string, string, string, error) {

		return "1", "2", "4", errors.New("error")
	})
	defer patch6.Reset()

	_, result := adapter.GetPodInfo(podList, nil, nil, "config2")
	assert.Error(t, result, "Test Get Pod Info2 execution result")
}

func TestGetResourcesBySelector(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(adapter.UpdatePodInfo, func(_ models.AppInfo, _ *models.LabelList, _ *kubernetes.Clientset,
		_ *rest.Config,
		_ string) (appInformation models.AppInfo, response map[string]string, err error) {

		return appInformation, response, nil
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(adapter.GetServiceInfo, func(_ *kubernetes.Clientset,
		_ metav1.ListOptions, _ string) (serviceInfo models.ServiceInfo, err error) {

		return serviceInfo, nil
	})
	defer patch3.Reset()
	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	kubeconfig := &rest.Config{
		Host:        https + net.JoinHostPort(hostIpAddress, "1234"),
		BearerToken: token,
	}
	var labelSelector models.LabelSelector
	var label models.LabelList
	var cs *kubernetes.Clientset

	label.Kind = util.Service
	label.Selector = "appName2"
	labelSelector.Label = append(labelSelector.Label, label)
	_, _, result := adapter.GetResourcesBySelector(labelSelector, cs, kubeconfig, namespace)
	assert.Nil(t, result, "Test Get resources by selector result")
}

func TestGetResourcesBySelector1(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(adapter.UpdatePodInfo, func(_ models.AppInfo, _ *models.LabelList, _ *kubernetes.Clientset,
		_ *rest.Config,
		_ string) (appInformation models.AppInfo, response map[string]string, err error) {

		return appInformation, response, nil
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(adapter.GetServiceInfo, func(_ *kubernetes.Clientset,
		_ metav1.ListOptions, _ string) (serviceInfo models.ServiceInfo, err error) {

		return serviceInfo, errors.New("error")
	})
	defer patch3.Reset()
	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	kubeconfig := &rest.Config{
		Host:        https + net.JoinHostPort(hostIpAddress, "1234"),
		BearerToken: token,
	}
	var labelSelector models.LabelSelector
	var label models.LabelList
	var cs *kubernetes.Clientset

	label.Kind = util.Service
	label.Selector = "appName3"
	labelSelector.Label = append(labelSelector.Label, label)
	_, _, result := adapter.GetResourcesBySelector(labelSelector, cs, kubeconfig, namespace)
	assert.Error(t, result, "Test Get resources by selector1 result")
}

func TestGetResourcesBySelector2(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(adapter.UpdatePodInfo, func(_ models.AppInfo, _ *models.LabelList, _ *kubernetes.Clientset,
		_ *rest.Config,
		_ string) (appInformation models.AppInfo, response map[string]string, err error) {

		return appInformation, response, errors.New("error")
	})
	defer patch2.Reset()

	patch3 := gomonkey.ApplyFunc(adapter.GetServiceInfo, func(_ *kubernetes.Clientset,
		_ metav1.ListOptions, _ string) (serviceInfo models.ServiceInfo, err error) {

		return serviceInfo, nil
	})
	defer patch3.Reset()
	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	kubeconfig := &rest.Config{
		Host:        https + net.JoinHostPort(hostIpAddress, "1234"),
		BearerToken: token,
	}
	var labelSelector models.LabelSelector
	var label models.LabelList
	var cs *kubernetes.Clientset

	label.Kind = util.Service
	label.Selector = "appName4"
	labelSelector.Label = append(labelSelector.Label, label)
	_, _, result := adapter.GetResourcesBySelector(labelSelector, cs, kubeconfig, namespace)
	assert.Error(t, result, "Test Get resources by selector2 result")
}

func TestUpdatePodInfo(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch3 := gomonkey.ApplyFunc(adapter.GetPods, func(_ *kubernetes.Clientset, _ string, _ *models.LabelList) (podList *v1.PodList, err error) {
		podList = &v1.PodList{Items: []v1.Pod{}}
		return podList, nil
	})
	defer patch3.Reset()
	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	kubeconfig := &rest.Config{
		Host:        https + net.JoinHostPort(hostIpAddress, "1234"),
		BearerToken: token,
	}
	//	var labelSelector models.LabelSelector
	var label models.LabelList
	var cs *kubernetes.Clientset
	var appInfo models.AppInfo

	label.Kind = "Pod"
	label.Selector = "appName5"

	_, _, result := adapter.UpdatePodInfo(appInfo, &label, cs, kubeconfig, namespace)
	assert.Nil(t, result, "Test Update Pod Info result")
}

func TestUpdatePodInfo2(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch3 := gomonkey.ApplyFunc(adapter.GetPods, func(_ *kubernetes.Clientset, _ string, _ *models.LabelList) (podList *v1.PodList, err error) {
		podList = &v1.PodList{Items: []v1.Pod{
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
				},
			},
		},
		}
		return podList, nil
	})
	defer patch3.Reset()
	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	kubeconfig := &rest.Config{
		Host:        https + net.JoinHostPort(hostIpAddress, "1234"),
		BearerToken: token,
	}
	//	var labelSelector models.LabelSelector
	var label models.LabelList
	var cs *kubernetes.Clientset
	var appInfo models.AppInfo

	label.Kind = "Pod"
	label.Selector = "appName6"

	_, _, result := adapter.UpdatePodInfo(appInfo, &label, cs, kubeconfig, namespace)
	assert.Nil(t, result, "Test Update Pod Info2 result")
}

func TestUpdatePodInfo3(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch3 := gomonkey.ApplyFunc(adapter.GetPods, func(_ *kubernetes.Clientset, _ string, _ *models.LabelList) (podList *v1.PodList, err error) {
		podList = &v1.PodList{Items: []v1.Pod{
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
				},
			},
		},
		}
		return podList, errors.New("error")
	})
	defer patch3.Reset()
	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	kubeconfig := &rest.Config{
		Host:        https + net.JoinHostPort(hostIpAddress, "1234"),
		BearerToken: token,
	}
	//	var labelSelector models.LabelSelector
	var label models.LabelList
	var cs *kubernetes.Clientset
	var appInfo models.AppInfo

	label.Kind = util.Deployment
	label.Selector = "appName7"

	_, _, result := adapter.UpdatePodInfo(appInfo, &label, cs, kubeconfig, namespace)
	assert.Error(t, result, "Test Update Pod Info3 result")
}

func TestGetTotalCpuDiskMemory(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch3 := gomonkey.ApplyFunc(adapter.GetNodeList, func(_ *kubernetes.Clientset) (nodeList *v1.NodeList, err error) {
		nodeList = &v1.NodeList{Items: []v1.Node{
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
				},
			},
		},
		}
		return nodeList, nil
	})
	defer patch3.Reset()
	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	var cs *kubernetes.Clientset

	_, _, _, result := adapter.GetTotalCpuDiskMemory(cs)
	assert.Nil(t, result, "Test Get Total Cpu Disk Memory result")
}

func TestGetTotalCpuDiskMemory2(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch3 := gomonkey.ApplyFunc(adapter.GetNodeList, func(_ *kubernetes.Clientset) (nodeList *v1.NodeList, err error) {
		nodeList = &v1.NodeList{Items: []v1.Node{
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
				},
			},
		},
		}
		return nodeList, errors.New("error")
	})
	defer patch3.Reset()
	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	var cs *kubernetes.Clientset

	_, _, _, result := adapter.GetTotalCpuDiskMemory(cs)
	assert.Error(t, result, "Test Get Total Cpu Disk Memory result")
}

func TestWorkloadEvents2(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	result, _ := client.WorkloadEvents(relName, namespace)
	assert.Equal(t, "", result, "Test workload events2 execution result")
}

func TestWorkloadEvents3(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(adapter.GetLabelSelector, func(_ []adapter.Manifest) (labelSelector models.LabelSelector) {
		var label models.LabelList

		label.Kind = "Pod"
		label.Selector = "appName8"
		labelSelector.Label = append(labelSelector.Label, label)
		return labelSelector
	})
	defer patch2.Reset()

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	var hc *adapter.HelmClient
	patch3 := gomonkey.ApplyMethod(reflect.TypeOf(hc), getClientSet,
		func(_ *adapter.HelmClient, _, _ string) (clientset *kubernetes.Clientset, manifest []adapter.Manifest, err error) {
			return clientset, manifest, nil
		})
	defer patch3.Reset()

	patch4 := gomonkey.ApplyFunc(adapter.UpdatePodDescInfo, func(_ models.PodDescribeInfo, _ *kubernetes.Clientset,
		_ models.LabelList, _ string) (podDescInfo models.PodDescribeInfo, err error) {

		return podDescInfo, nil
	})
	defer patch4.Reset()

	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	result, _ := client.WorkloadEvents(relName, namespace)
	assert.Equal(t, "{\"pods\":null}", result, "Test workload events3 execution result")
}

func TestWorkloadEvents4(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(adapter.GetLabelSelector, func(_ []adapter.Manifest) (labelSelector models.LabelSelector) {
		var label models.LabelList

		label.Kind = "Pod"
		label.Selector = "appName9"
		labelSelector.Label = append(labelSelector.Label, label)
		return labelSelector
	})
	defer patch2.Reset()

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	var hc *adapter.HelmClient
	patch3 := gomonkey.ApplyMethod(reflect.TypeOf(hc), getClientSet,
		func(_ *adapter.HelmClient, _, _ string) (clientset *kubernetes.Clientset, manifest []adapter.Manifest, err error) {
			return clientset, manifest, nil
		})
	defer patch3.Reset()

	patch4 := gomonkey.ApplyFunc(adapter.UpdatePodDescInfo, func(_ models.PodDescribeInfo, _ *kubernetes.Clientset,
		_ models.LabelList, _ string) (podDescInfo models.PodDescribeInfo, err error) {

		return podDescInfo, nil
	})
	defer patch4.Reset()

	patch5 := gomonkey.ApplyFunc(json.Marshal, func(_ interface{}) (b []byte, err error) {
		// do nothing
		return b, errors.New("error")
	})
	defer patch5.Reset()

	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	result, _ := client.WorkloadEvents(relName, namespace)
	assert.Equal(t, "", result, "Test workload events4 execution result")
}

func TestWorkloadEvents5(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(adapter.GetLabelSelector, func(_ []adapter.Manifest) (labelSelector models.LabelSelector) {
		var label models.LabelList

		label.Kind = "Pod"
		label.Selector = "appName10"
		labelSelector.Label = append(labelSelector.Label, label)
		return labelSelector
	})
	defer patch2.Reset()

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	var hc *adapter.HelmClient
	patch3 := gomonkey.ApplyMethod(reflect.TypeOf(hc), getClientSet,
		func(_ *adapter.HelmClient, _, _ string) (clientset *kubernetes.Clientset, manifest []adapter.Manifest, err error) {
			return clientset, manifest, nil
		})
	defer patch3.Reset()

	patch4 := gomonkey.ApplyFunc(adapter.UpdatePodDescInfo, func(_ models.PodDescribeInfo, _ *kubernetes.Clientset,
		_ models.LabelList, _ string) (podDescInfo models.PodDescribeInfo, err error) {

		return podDescInfo, errors.New("error")
	})
	defer patch4.Reset()

	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	result, _ := client.WorkloadEvents(relName, namespace)
	assert.Equal(t, "", result, "Test workload events5 execution result")
}

func TestGetPodDescInfo(_ *testing.T) {
	patch1 := gomonkey.ApplyFunc(adapter.NewHelmClient, func(tenantId string, _ string) (*adapter.HelmClient, error) {
		// do nothing
		return &adapter.HelmClient{HostIP: ipAddress, Kubeconfig: configFile + tenantId + "/" + ipAddress}, nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(adapter.GetEvents, func(_ *kubernetes.Clientset,
		_ string, _ *v1.ObjectReference) (events *v1.EventList) {
		events = &v1.EventList{Items: []v1.Event{}}
		return events
	})
	defer patch2.Reset()

	client, _ := adapter.NewHelmClient(tenantId, hostIpAddress)
	var cs *kubernetes.Clientset

	baseDir, _ := os.Getwd()
	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress

	client.Kubeconfig = baseDir + directory + "/" + hostIpAddress
	ref := &v1.ObjectReference{
		Kind:       util.Deployment,
		APIVersion: "v1",
		Name:       "name",
		Namespace:  namespace,
	}

	pod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
	}

	_ = adapter.GetPodDescInfo(ref, pod, cs, "pod", namespace)
}
