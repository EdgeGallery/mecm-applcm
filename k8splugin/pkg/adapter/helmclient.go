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
	"errors"
	"fmt"
	"github.com/ghodss/yaml"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/metrics/pkg/apis/metrics/v1beta1"
	metrics "k8s.io/metrics/pkg/client/clientset/versioned"
	"k8splugin/config"
	"k8splugin/models"
	"k8splugin/pgdb"
	"k8splugin/util"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/reference"
	"k8s.io/kubectl/pkg/scheme"
)

// Variables to be defined in deployment file
var (
	kubeconfigPath   = "/usr/app/config/"
)

// Helm client
type HelmClient struct {
	HostIP     string
	Kubeconfig string
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
		return &HelmClient{HostIP: hostIP, Kubeconfig: kubeconfigPath + hostIP}, nil
	} else {
		log.Error("No file exist with name")
		return nil, err
	}
}

// Install a given helm chart
func (hc *HelmClient) Deploy(pkg bytes.Buffer, appInsId string, ak string, sk string, db pgdb.Database) (string, error) {
	log.Info("Inside helm client")

	// Create temporary file to hold helm chart
	file, err := os.Create(util.TempFile)
	if err != nil {
		log.Error("Unable to create file")
		return "", err
	}
	defer os.Remove(util.TempFile)

	// Write input bytes to temp file
	_, err = pkg.WriteTo(file)
	if err != nil {
		log.Error("Unable to write to file")
		return "", err
	}

	tarFile, err := os.Open(util.TempFile)
	if err != nil {
		log.Error("Failed to open the tar file")
		return "", err
	}
	defer tarFile.Close()

	appAuthCfg := config.NewBuildAppAuthConfig(appInsId, ak, sk)
	dirName, err := appAuthCfg.AddValues(tarFile)
	if err != nil {
		log.Error("Failed to add values in values file")
		return "", err
	}
	defer os.Remove(dirName + ".tar.gz")
	defer  os.RemoveAll(dirName)
	// Load the file to chart
	chart, err := loader.Load(dirName + ".tar.gz")
	if err != nil {
		log.Error("Unable to load chart from file")
		return "", err
	}

	// Release name will be taken from the name in chart's metadata
	relName := chart.Metadata.Name

	appInstanceRecord := &models.AppInstanceInfo{
		WorkloadId: relName,
	}

	readErr := db.ReadData(appInstanceRecord, "workload_id")
	if readErr == nil {
		return "", errors.New("application is already deployed with this release name")
	}

	// Get release namespace
	releaseNamespace := util.GetReleaseNamespace()

	// Initialize action config
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(hc.Kubeconfig, "", releaseNamespace), releaseNamespace,
		util.HelmDriver, func(format string, v ...interface{}) {
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
		ui := action.NewUninstall(actionConfig)
		_, uninstallErr := ui.Run(relName)
		if uninstallErr != nil {
			log.Infof("Unable to uninstall chart. Err: %s", uninstallErr)
		}
		log.Errorf("Unable to install chart. Err: %s", err)
		return "", err
	}
	log.Info("Successfully created chart")
	return rel.Name, err
}

// Un-Install a given helm chart
func (hc *HelmClient) UnDeploy(relName string) error {
	// Get release namespace
	releaseNamespace := util.GetReleaseNamespace()

	// Prepare action config and uninstall chart
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(hc.Kubeconfig, "", releaseNamespace), releaseNamespace,
		util.HelmDriver, func(format string, v ...interface{}) {
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
func (hc *HelmClient) Query(relName string) (string, error) {
	log.Info("In Query Chart function")

	// Get release namespace
	releaseNamespace := util.GetReleaseNamespace()
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(hc.Kubeconfig, "", releaseNamespace), releaseNamespace,
		util.HelmDriver, func(format string, v ...interface{}) {
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

	// uses the current context in kubeconfig
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", hc.Kubeconfig)
	if err != nil {
		return "", err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return "", err
	}
	
	labelSelector := getLabelSelector(manifest)

	appInfo, response, err := getResourcesBySelector(labelSelector, clientset, kubeConfig)
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

// Get pod description
func (hc *HelmClient) WorkloadDescribe(relName string) (string, error) {
	log.Info("In Pod describe function")
	var podDesc models.PodDescribeInfo

	clientset, manifest, err := hc.getClientSet(relName)
	if nil != err {
		return "", err
	}

	labelSelector := getLabelSelector(manifest)

	for _, label := range labelSelector.Label {
		if label.Kind == util.Pod || label.Kind == util.Deployment {
			podDesc, err = updatePodDescInfo(podDesc, clientset, label)
			if err != nil {
				return "", err
			}
		}
	}
	podDescInfoJson, err := json.Marshal(podDesc)
	if err != nil {
		log.Info(util.FailedToJsonMarshal)
		return "", err
	}
	return string(podDescInfoJson), nil
}

func updatePodDescInfo(podDesc models.PodDescribeInfo, clientset *kubernetes.Clientset,
	label models.Label) (models.PodDescribeInfo, error) {
	options := metav1.ListOptions{
		LabelSelector: label.Selector,
	}
	pods, err := clientset.CoreV1().Pods(util.Default).List(context.Background(), options)
	if err != nil {
		return podDesc, err
	}
	for _, podItem := range pods.Items {
		podName := podItem.GetObjectMeta().GetName()
		pod, err := clientset.CoreV1().Pods(util.Default).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			return podDesc, err
		}

		if ref, err := reference.GetReference(scheme.Scheme, pod); err != nil {
			log.Errorf("Unable to construct reference to '%#v': %v", pod, err)
			return podDesc, err
		} else {
			podDescInfo := getPodDescInfo(ref, pod, clientset, podName)
			podDesc.PodDescInfo = append(podDesc.PodDescInfo, podDescInfo)
		}
	}
	return podDesc, nil
}

func (hc *HelmClient) getClientSet(relName string) (clientset *kubernetes.Clientset, manifest []Manifest, err error) {
	// Get release namespace
	releaseNamespace := util.GetReleaseNamespace()
	actionConfig := new(action.Configuration)
	if err = actionConfig.Init(kube.GetConfig(hc.Kubeconfig, "", releaseNamespace), releaseNamespace,
		util.HelmDriver, func(format string, v ...interface{}) {
			_ = fmt.Sprintf(format, v)
		}); err != nil {
		log.Error(util.ActionConfig)
		return clientset, manifest, err
	}
	s := action.NewStatus(actionConfig)
	res, err := s.Run(relName)
	if err != nil {
		log.Error("Unable to query chart with release name")
		return clientset, manifest, err
	}
	manifest, err = splitManifestYaml([]byte(res.Manifest))
	if err != nil {
		log.Errorf("Query response processing failed release name: %s. Err: %s",
			relName, err)
		return clientset, manifest, err
	}

	// uses the current context in kubeconfig
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", hc.Kubeconfig)
	if err != nil {
		return clientset, manifest, err
	}
	// creates the clientset
	clientset, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return clientset, manifest, err
	}
	return clientset, manifest, nil
}

func getPodDescInfo(ref *v1.ObjectReference, pod *v1.Pod, clientset *kubernetes.Clientset,
	podName string) (podDescInfo models.PodDescInfo) {
	ref.Kind = ""
	if _, isMirrorPod := pod.Annotations[corev1.MirrorPodAnnotationKey]; isMirrorPod {
		ref.UID = types.UID(pod.Annotations[corev1.MirrorPodAnnotationKey])
	}
	events, _ := clientset.CoreV1().Events(util.Default).Search(scheme.Scheme, ref)
	podDescInfo.PodName = podName
	if len(events.Items) == 0 {
		podDescInfo.PodEventsInfo = append(podDescInfo.PodEventsInfo,
			"Pod is running successfully")
	}
	for _, e := range events.Items {
		podDescInfo.PodEventsInfo = append(podDescInfo.PodEventsInfo, strings.TrimSpace(e.Message))
	}
	return podDescInfo
}

// Get label selector
func getLabelSelector(manifest []Manifest) models.LabelSelector {
	var labelSelector models.LabelSelector
	var label models.Label

	for i := 0; i < len(manifest); i++ {
		if manifest[i].Kind == util.Deployment || manifest[i].Kind == util.Pod || manifest[i].Kind == "Service" {
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

	return labelSelector
}

// get JSON response
func getJSONResponse(appInfo models.AppInfo, response map[string]string) (string, error) {
	if response != nil {
		appInfoJson, err := json.Marshal(response)
		if err != nil {
			log.Info(util.FailedToJsonMarshal)
			return "", err
		}
		return string(appInfoJson), nil
	}

	appInfoJson, err := json.Marshal(appInfo)
	if err != nil {
		log.Info(util.FailedToJsonMarshal)
		return "", err
	}

	return string(appInfoJson), nil
}

// Get resources by selector
func getResourcesBySelector(labelSelector models.LabelSelector, clientset *kubernetes.Clientset,
	config *rest.Config) (appInfo models.AppInfo, response map[string]string, err error) {

	for _, label := range labelSelector.Label {
		if label.Kind == util.Pod || label.Kind == util.Deployment {
			options := metav1.ListOptions{
				LabelSelector: label.Selector,
			}

			pods, err := clientset.CoreV1().Pods(util.Default).List(context.Background(), options)
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
		cpu := container.Usage.Cpu().MilliValue()
		cpuUsage := strconv.FormatInt(cpu, 10)
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
			cpu := cpuquantity.MilliValue()
			totalCpuUsage = strconv.FormatInt(cpu, 10)
			memQuantity := node.Status.Allocatable.Memory()
			memory, _ := memQuantity.AsInt64()
			totalMemUsage = strconv.FormatInt(memory, 10)
			diskQuantity := node.Status.Allocatable.StorageEphemeral()
			disk, _ := diskQuantity.AsInt64()
			totalDiskUsage = strconv.FormatInt(disk, 10)
		}
		return totalCpuUsage, totalMemUsage, totalDiskUsage, err
	}
	return "", "", "", err
}

// Split manifest yaml file
func splitManifestYaml(data []byte) (manifest []Manifest, err error) {
	manifestBuf := []Manifest{}

	yamlSeparator := "\n---"
	yamlString := string(data)

	yamls := strings.Split(yamlString, yamlSeparator)
	for k := 0; k < len(yamls); k++ {
		var manifest Manifest
		err := yaml.Unmarshal([]byte(yamls[k]), &manifest)
		if err != nil {
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
