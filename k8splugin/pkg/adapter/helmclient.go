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

package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"k8splugin/models"
	"k8splugin/util"
	"os"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/metrics/pkg/apis/metrics/v1beta1"

	log "github.com/sirupsen/logrus"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	metrics "k8s.io/metrics/pkg/client/clientset/versioned"
)

// Variables to be defined in deployment file
var (
	chartPath        = os.Getenv("CHART_PATH")
	kubeconfigPath   = "/usr/app/config/"
	releaseNamespace = os.Getenv("RELEASE_NAMESPACE")
)

// Helm client
type HelmClient struct {
	hostIP     string
	kubeconfig string
}

// Manifest file
type Manifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
		Labels    struct {
			App       string `yaml:"app"`
			Component string `yaml:"component"`
		} `yaml:"labels"`
	} `yaml:"metadata"`
	Spec struct {
		Selector struct {
			MatchLabels struct {
				App string `yaml:"app"`
			} `yaml:"matchLabels"`
		} `yaml:"selector"`
		Replicas int `yaml:"replicas"`
		Template struct {
			Metadata struct {
				Labels struct {
					App string `yaml:"app"`
				} `yaml:"labels"`
			} `yaml:"metadata"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

// Constructor of helm client for a given host IP
func NewHelmClient(hostIP string) (*HelmClient, error) {
	// Kubeconfig file will be picked based on host IP and will be check for existence
	exists, err := fileExists(kubeconfigPath + hostIP)
	if exists {
		return &HelmClient{hostIP: hostIP, kubeconfig: kubeconfigPath + hostIP}, nil
	} else {
		log.Error("No file exist with name")
		return nil, err
	}
}

// Install a given helm chart
func (hc *HelmClient) InstallChart(helmPkg bytes.Buffer) (string, error) {
	log.Info("Inside helm client")

	// Create temporary file to hold helm chart
	file, err := os.Create(chartPath + util.TempFile)
	if err != nil {
		log.Error("Unable to create file")
		return "", err
	}
	defer os.Remove(chartPath + util.TempFile)

	// Write input bytes to temp file
	_, err = helmPkg.WriteTo(file)
	if err != nil {
		log.Error("Unable to write to file")
		return "", err
	}

	// Load the file to chart
	chart, err := loader.Load(chartPath + util.TempFile)
	if err != nil {
		log.Error("Unable to load chart from file")
		return "", err
	}

	// Release name will be taken from the name in chart's metadata
	relName := chart.Metadata.Name

	// Initialize action config
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(hc.kubeconfig, "", releaseNamespace), releaseNamespace,
		os.Getenv(util.HelmDriver), func(format string, v ...interface{}) {
			_ = fmt.Sprintf(format, v)
		}); err != nil {
		log.Error(util.ActionConfig)
		return "", err
	}

	// Prepare chart install action and install chart
	installer := action.NewInstall(actionConfig)
	installer.Namespace = releaseNamespace
	installer.ReleaseName = relName
	rel, err := installer.Run(chart, nil)
	if err != nil {
		log.Errorf("Unable to install chart. Err: %s", err)
		return "", err
	}
	log.Info("Successfully created chart")
	return rel.Name, err
}

// Un-Install a given helm chart
func (hc *HelmClient) UninstallChart(relName string) error {
	// Prepare action config and uninstall chart
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(hc.kubeconfig, "", releaseNamespace), releaseNamespace,
		os.Getenv(util.HelmDriver), func(format string, v ...interface{}) {
			_ = fmt.Sprintf(format, v)
		}); err != nil {
		log.Error(util.ActionConfig)
		return err
	}

	ui := action.NewUninstall(actionConfig)
	res, err := ui.Run(relName)
	if err != nil {
		log.Errorf("Unable to uninstall chart. Err: %s", err)
		return err
	}
	log.Infof("Successfully uninstalled chart. Response Info: %s", res.Info)
	return nil
}

// Query a given chart
func (hc *HelmClient) QueryChart(relName string) (string, error) {
	log.Info("In Query Chart function")
	var labelSelector models.LabelSelector
	var label models.Label

	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(hc.kubeconfig, "", releaseNamespace), releaseNamespace,
		os.Getenv(util.HelmDriver), func(format string, v ...interface{}) {
			_ = fmt.Sprintf(format, v)
		}); err != nil {
		log.Error(util.ActionConfig)
		return "", err
	}
	s := action.NewStatus(actionConfig)
	res, err := s.Run(relName)
	if err != nil {
		log.Error("Unable to query chart with release name")
		return "", err
	}
	manifest, err := splitManifestYaml([]byte(res.Manifest))
	if err != nil {
		log.Errorf("Query response processing failed release name: %s. Err: %s",
			relName, err)
		return "", err
	}

	for i := 0; i < len(manifest); i++ {
		if manifest[i].Kind == "Deployment" || manifest[i].Kind == "Pod" || manifest[i].Kind == "Service" {
			appName := manifest[i].Metadata.Name
			if manifest[i].Metadata.Labels.App != "" {
				appName = manifest[i].Metadata.Labels.App
			}
			pod := "app=" + appName
			label.Kind = manifest[i].Kind
			label.Selector = pod
			labelSelector.Label = append(labelSelector.Label, label)
		}
	}

	// uses the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", hc.kubeconfig)
	if err != nil {
		return "", err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", err
	}

	appInfo, response, err := getResourcesBySelector(labelSelector, clientset, config)
	if err != nil {
		log.Error("Failed to get pod statistics")
		return "", err
	}

	appInfoJson, err := getJSONResponse(appInfo, response)
	if err != nil {
		return "", err
	}
	return appInfoJson, nil

}

// get JSON response
func getJSONResponse(appInfo models.AppInfo, response map[string]string) (string, error) {
	if response != nil {
		appInfoJson, err := json.Marshal(response)
		if err != nil {
			log.Info("Failed to json marshal")
			return "", err
		}
		return string(appInfoJson), nil
	}

	appInfoJson, err := json.Marshal(appInfo)
	if err != nil {
		log.Info("Failed to json marshal")
		return "", err
	}

	return string(appInfoJson), nil
}

// Get resources by selector
func getResourcesBySelector(labelSelector models.LabelSelector, clientset *kubernetes.Clientset,
	config *rest.Config) (appInfo models.AppInfo, response map[string]string, err error) {

	for _, label := range labelSelector.Label {
		if label.Kind == "Pod" || label.Kind == "Deployment" {
			options := metav1.ListOptions{
				LabelSelector: label.Selector,
			}

			pods, err := clientset.CoreV1().Pods("default").List(context.Background(), options)
			if err != nil {
				return appInfo, nil, err
			}
			if len(pods.Items) == 0 {
				response := map[string]string{"status": "not running"}
				return appInfo, response, nil
			}

			podInfo, err := getPodInfo(pods, clientset, config)
			if err != nil {
				return appInfo, nil, err
			}

			appInfo.Pods = append(appInfo.Pods, podInfo)
		}
	}

	return appInfo, nil, nil
}

// Get pod information
func getPodInfo(pods *v1.PodList, clientset *kubernetes.Clientset, config *rest.Config) (podInfo models.PodInfo, err error) {
	for _, pod := range pods.Items {
		podName := pod.GetObjectMeta().GetName()
		podMetrics, err := getPodMetrics(config, podName)
		if err != nil {
			return podInfo, err
		}

		podInfo, err = updateContainerInfo(podMetrics, clientset, podInfo)
		if err != nil {
			return podInfo, err
		}

		podInfo.PodName = podName
		phase := pod.Status.Phase
		podInfo.PodStatus = string(phase)
	}

	return podInfo, nil
}

// Update container information
func updateContainerInfo(podMetrics *v1beta1.PodMetrics, clientset *kubernetes.Clientset, podInfo models.PodInfo) (models.PodInfo, error) {
	var containerInfo models.ContainerInfo
	totalCpuUsage, totalMemUsage, totalDiskUsage, err := getTotalCpuDiskMemory(clientset)
	if err != nil {
		return podInfo, err
	}

	for _, container := range podMetrics.Containers {
		cpuUsage := container.Usage.Cpu().String()
		cpuUsage = strings.TrimSuffix(cpuUsage, "n")
		memory, _ := container.Usage.Memory().AsInt64()
		memUsage := strconv.FormatInt(memory, 10)
		disk, _ := container.Usage.StorageEphemeral().AsInt64()
		diskUsage := strconv.FormatInt(disk, 10)

		containerInfo.ContainerName = container.Name
		containerInfo.MetricsUsage.CpuUsage = cpuUsage + "/" + totalCpuUsage
		containerInfo.MetricsUsage.MemUsage = memUsage + "/" + totalMemUsage
		containerInfo.MetricsUsage.DiskUsage = diskUsage + "/" + totalDiskUsage
		podInfo.Containers = append(podInfo.Containers, containerInfo)
	}
	return podInfo, nil
}

// Get Pod metrics
func getPodMetrics(config *rest.Config, podName string) (podMetrics *v1beta1.PodMetrics, err error) {
	mc, err := metrics.NewForConfig(config)
	if err != nil {
		return podMetrics, err
	}

	podMetrics, err = mc.MetricsV1beta1().PodMetricses(metav1.NamespaceDefault).Get(context.Background(),
		podName, metav1.GetOptions{})
	if err != nil {
		return podMetrics, err
	}
	return podMetrics, nil
}

// Get total cpu disk and memory metrics
func getTotalCpuDiskMemory(clientset *kubernetes.Clientset) (string, string, string, error) {
	var totalDiskUsage string
	var totalMemUsage string
	var totalCpuUsage string

	nodeList, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err == nil {
		if len(nodeList.Items) > 0 {
			node := &nodeList.Items[0]
			cpuquantity := node.Status.Allocatable.Cpu()
			cpu, _ := cpuquantity.AsInt64()
			cpu = cpu * 1000000
			totalCpuUsage = strconv.FormatInt(cpu, 10)
			memQuantity := node.Status.Allocatable.Memory()
			memory, _ := memQuantity.AsInt64()
			totalMemUsage = strconv.FormatInt(memory, 10)
			diskQuantity := node.Status.Allocatable.StorageEphemeral()
			disk, _ := diskQuantity.AsInt64()
			totalDiskUsage = strconv.FormatInt(disk, 10)
		}
	} else {
		return "", "", "", err
	}
	return totalCpuUsage, totalMemUsage, totalDiskUsage, err

}

// Split manifest yaml file
func splitManifestYaml(data []byte) (manifest []Manifest, err error) {
	manifestBuf := []Manifest{}

	yamlSeparator := "\n---"
	yamlString := string(data)

	yamls := strings.Split(yamlString, yamlSeparator)
	//fmt.Println("yamls:  ", yamls)
	for k := 0; k < len(yamls); k++ {
		var manifest Manifest
		err := yaml.Unmarshal([]byte(yamls[k]), &manifest)
		if err != nil {
			fmt.Printf("err: %v\n", err)
			return nil, err
		}
		manifestBuf = append(manifestBuf, manifest)
	}
	return manifestBuf, nil
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func fileExists(filename string) (bool, error) {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false, err
	}
	return !info.IsDir(), nil
}
