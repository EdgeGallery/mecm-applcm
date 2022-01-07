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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ghodss/yaml"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"k8s.io/metrics/pkg/apis/metrics/v1beta1"
	metrics "k8s.io/metrics/pkg/client/clientset/versioned"
	"k8splugin/config"
	"k8splugin/models"
	"k8splugin/pgdb"
	"k8splugin/util"
	"os"
	"path/filepath"
	"reflect"
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
	kubeconfigPath              = "/usr/app/artifacts/config/"
	appPackagesBasePath         = "/usr/app/artifacts/packages/"
	totalCpu1           float64 = 0
	totalMem1           float64 = 0
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
func NewHelmClient(tenantId string, hostIP string) (*HelmClient, error) {
	// Kubeconfig file will be picked based on host IP and will be check for existence
	exists, err := fileExists(kubeconfigPath + tenantId + "/" + hostIP)
	if exists {
		return &HelmClient{HostIP: hostIP, Kubeconfig: kubeconfigPath + tenantId + "/" + hostIP}, nil
	} else {
		log.Error("No file exist with name")
		return nil, err
	}
}

// Install a given helm chart
func (hc *HelmClient) Deploy(appPkgRecord *models.AppPackage, appInsId, ak, sk string, db pgdb.Database) (string, string, error) {
	log.Info("Inside helm client")

	helmChart, err := hc.getHelmChart(appPkgRecord.TenantId, appPkgRecord.HostIp, appPkgRecord.PackageId)
	tarFile, err := os.Open(helmChart)
	if err != nil {
		log.Error("Failed to open helm chart tar file")
		return "", "", err
	}
	defer tarFile.Close()

	appAuthCfg := config.NewBuildAppAuthConfig(appInsId, ak, sk)
	dirName, namespace, err := appAuthCfg.AddValues(tarFile)
	if err != nil {
		log.Error("Failed to add values in values file")
		return "", "", err
	}
	defer os.Remove(dirName + ".tar.gz")
	defer os.RemoveAll(dirName)

	log.WithFields(log.Fields{
		"helm_chart":      dirName,
		"app_instance_id": appInsId,
		"namespace":       namespace,
	}).Info("deployment chart")

	// Load the file to chart
	chart, err := loader.Load(dirName + ".tar.gz")
	if err != nil {
		log.Error("Unable to load chart from file")
		return "", "", err
	}

	if namespace != util.Default {

		// uses the current context in kubeconfig
		kubeConfig, err := clientcmd.BuildConfigFromFlags("", hc.Kubeconfig)
		if err != nil {
			return "", "", err
		}

		clientSet, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			log.Error("failed to get clientset")
			return "", "", err
		}

		nsName := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			},
		}

		_, err = clientSet.CoreV1().Namespaces().Create(context.Background(), nsName, metav1.CreateOptions{})
		if err != nil {
			log.Error("failed to create namespace")
			return "", "", err
		}
	}

	// Release name will be taken from the name in chart's metadata
	relName := chart.Metadata.Name

	appInstanceRecord := &models.AppInstanceInfo{
		WorkloadId: relName,
	}

	readErr := db.ReadData(appInstanceRecord, "workload_id")
	if readErr == nil {
		return "", "", errors.New("application is already deployed with this release name")
	}

	// Initialize action config
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(hc.Kubeconfig, "", namespace), namespace,
		util.HelmDriver, func(format string, v ...interface{}) {
			_ = fmt.Sprintf(format, v)
		}); err != nil {
		log.Error(util.ActionConfig)
		return "", "", err
	}

	// Prepare chart install action and install chart
	installer := action.NewInstall(actionConfig)
	installer.Namespace = namespace // so if we want to deploy helm charts via k8splugin.. first namespace should be created or exist then we can deploy helm charts in that namespace
	installer.ReleaseName = relName

	rel, err := installer.Run(chart, nil)
	if err != nil {
		ui := action.NewUninstall(actionConfig)
		_, uninstallErr := ui.Run(relName)
		if uninstallErr != nil {
			log.Infof("Unable to uninstall chart. Err: %s", uninstallErr)
		}
		log.Errorf("Unable to install chart. Err: %s", err)
		return "", "", err
	}
	log.Info("Successfully created chart")
	return rel.Name, namespace, err
}

// Un-Install a given helm chart
func (hc *HelmClient) UnDeploy(relName, namespace string) error {

	// Prepare action config and uninstall chart
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(hc.Kubeconfig, "", namespace), namespace,
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

	if namespace != util.Default {
		// uses the current context in kubeconfig
		kubeConfig, err := clientcmd.BuildConfigFromFlags("", hc.Kubeconfig)
		if err != nil {
			return err
		}

		clientSet, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			log.Error("failed to get clientset")
			return err
		}

		err = clientSet.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
		if err != nil {
			log.Error("failed to create namespace")
			return err
		}
	}
	log.Infof("Successfully uninstalled chart. Response Info: %s", res.Info)
	return nil
}

// Query a given chart
func (hc *HelmClient) Query(relName, namespace string) (string, error) {
	log.Info("In Query Chart function")

	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(kube.GetConfig(hc.Kubeconfig, "", namespace), namespace,
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
	manifest, err := SplitManifestYaml([]byte(res.Manifest))
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

	labelSelector := GetLabelSelector(manifest)

	appInfo, response, err := GetResourcesBySelector(labelSelector, clientset, kubeConfig, namespace)
	if err != nil {
		log.Error("Failed to get pod statistics")
		return "", err
	}

	appInfoJson, err := GetJSONResponse(appInfo, response)
	if err != nil {
		return "", err
	}
	return appInfoJson, nil
}

// Query KPI
func (hc *HelmClient) QueryKPI() (string, error) {
	log.Info("In Query KPI function")
	var metricInfo models.MetricInfo
	var totalCpu int64
	var totalMem int64
	var totalPodCpu int64
	var totalPodMem int64

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

	var statsInfo map[string]interface{}
	data, err := clientset.RESTClient().Get().AbsPath("apis/metrics.k8s.io/v1beta1/nodes").DoRaw(context.Background())

	_ = json.Unmarshal(data, &statsInfo)

	totalCpu, totalMem = getNodeTotalCpuMem(statsInfo)

	var statsInfo1 map[string]interface{}
	data1, err := clientset.RESTClient().Get().AbsPath("apis/metrics.k8s.io/v1beta1/pods").DoRaw(context.Background())
	_ = json.Unmarshal(data1, &statsInfo1)

	totalPodCpu, totalPodMem = getPodTotalCpuMem(statsInfo1)

	metricInfo.CpuUsage = make(map[string]int64)
	metricInfo.MemUsage = make(map[string]int64)

	metricInfo.CpuUsage["total"] = totalCpu
	metricInfo.MemUsage["total"] = totalMem

	metricInfo.CpuUsage["used"] = totalPodCpu
	metricInfo.MemUsage["used"] = totalPodMem
	result := &models.ReturnResponse{
		Data:    metricInfo,
		RetCode: 0,
		Message: "success",
		Params:  nil,
	}
	metricInfoJson, err := json.Marshal(result)
	if err != nil {
		log.Info(util.FailedToJsonMarshal)
		return "", err
	}
	return string(metricInfoJson), nil
}

func getPodTotalCpuMem(statsInfo1 map[string]interface{}) (totalPodCpu, totalPodMem int64) {
	for key, value := range statsInfo1 {
		if key == "items" {
			items := value.([]interface{})
			arr := reflect.ValueOf(items)
			for i := 0; i < arr.Len(); i++ {
				usage := arr.Index(i).Interface()
				totalPodCpu, totalPodMem = getPodCpuMemUsageInfo(usage, totalPodCpu, totalPodMem)
			}
		}
	}
	return totalPodCpu, totalPodMem
}

func getPodCpuMemUsageInfo(usage interface{}, totalPodCpu, totalPodMem int64) (int64, int64) {
	iter := reflect.ValueOf(usage).MapRange()
	for iter.Next() {

		if iter.Key().Interface() == "containers" {
			containersList := iter.Value().Interface()
			arr1 := reflect.ValueOf(containersList)
			totalPodCpu, totalPodMem = getTotalPodCpuMem(arr1, totalPodCpu, totalPodMem)
		}
	}
	return totalPodCpu, totalPodMem
}

func getTotalPodCpuMem(arr1 reflect.Value, totalPodCpu, totalPodMem int64) (int64, int64) {
	for j := 0; j < arr1.Len(); j++ {
		usage1 := arr1.Index(j).Interface()
		iter1 := reflect.ValueOf(usage1).MapRange()
		for iter1.Next() {
			totalPodCpu, totalPodMem = processUsage(iter1, totalPodCpu, totalPodMem)
		}
	}
	return totalPodCpu, totalPodMem
}

func processUsage(iter1 *reflect.MapIter, totalPodCpu, totalPodMem int64) (int64, int64) {
	if iter1.Key().Interface() == "usage" {
		val := iter1.Value().Interface()
		iter2 := reflect.ValueOf(val).MapRange()
		for iter2.Next() {
			if iter2.Key().Interface() == "cpu" {
				cpuVal := iter2.Value().Interface()
				cpu := cpuVal.(string)
				cpuLen := len(cpu)
				cpu = cpu[:cpuLen-1]
				cpuInfo, _ := strconv.ParseInt(cpu, 10, 64);
				totalPodCpu = totalPodCpu + cpuInfo
			}
			if iter2.Key().Interface() == "memory" {
				memory := iter2.Value().Interface()
				mem := memory.(string)
				memLen := len(mem)
				mem = mem[:memLen-2]
				memInfo, _ := strconv.ParseInt(mem, 10, 64);
				totalPodMem = totalPodMem + memInfo
			}
		}
	}
	return totalPodCpu, totalPodMem
}

func getNodeTotalCpuMem(statsInfo map[string]interface{}) (totalCpu, totalMem int64) {
	for key, value := range statsInfo {
		if key == "items" {
			items := value.([]interface{})
			arr := reflect.ValueOf(items)
			for i := 0; i < arr.Len(); i++ {
				usage := arr.Index(i).Interface()
				totalCpu, totalMem = getCpuMemUsageInfo(usage, totalCpu, totalMem)
			}
		}
	}
	return totalCpu, totalMem
}

func getCpuMemUsageInfo(usage interface{}, totalCpu, totalMem int64) (int64, int64) {
	iter := reflect.ValueOf(usage).MapRange()
	for iter.Next() {
		if iter.Key().Interface() == "usage" {
			val := iter.Value().Interface()
			iter1 := reflect.ValueOf(val).MapRange()
			for iter1.Next() {
				if iter1.Key().Interface() == "cpu" {
					cpuVal := iter1.Value().Interface()
					cpu := cpuVal.(string)
					cpuLen := len(cpu)
					cpu = cpu[:cpuLen-1]
					cpuInfo, _ := strconv.ParseInt(cpu, 10, 64);
					totalCpu = totalCpu + cpuInfo
				}
				if iter1.Key().Interface() == "memory" {
					memory := iter1.Value().Interface()
					mem := memory.(string)
					memLen := len(mem)
					mem = mem[:memLen-2]
					memInfo, _ := strconv.ParseInt(mem, 10, 64);
					totalMem = totalMem + memInfo
				}
			}
		}
	}
	return totalCpu, totalMem
}

// Get workload description
func (hc *HelmClient) WorkloadEvents(relName, namespace string) (string, error) {
	log.Info("In Workload describe function")
	var podDesc models.PodDescribeInfo

	clientset, manifest, err := hc.GetClientSet(relName, namespace)
	if nil != err {
		return "", err
	}

	labelSelector := GetLabelSelector(manifest)

	for _, label := range labelSelector.Label {
		if label.Kind == util.Pod || label.Kind == util.Deployment {
			podDesc, err = UpdatePodDescInfo(podDesc, clientset, label, namespace)
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

// Get helm chart
func (c *HelmClient) getHelmChart(tenantId, hostIp, packageId string) (string, error) {

	pkgPath := appPackagesBasePath + tenantId + "/" + packageId + hostIp + "/Artifacts/Deployment/Charts"
	artifact, _ := GetDeploymentArtifact(pkgPath, ".tar")
	if artifact == "" {
		log.Error("Artifact not available in application package.")
		return "", errors.New("Helm chart not available in application package.")
	}
	return artifact, nil
}

// Gets deployment artifact
func GetDeploymentArtifact(dir string, ext string) (string, error) {
	d, err := os.Open(dir)
	if err != nil {
		log.Info("failed to open the directory")
		return "", err
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		log.Info("failed to read the directory")
		return "", err
	}

	for _, file := range files {
		if file.Mode().IsRegular() && (filepath.Ext(file.Name()) == ext ||
			filepath.Ext(file.Name()) == ".gz" || filepath.Ext(file.Name()) == ".tgz") {
			return dir + "/" + file.Name(), nil
		}
	}
	return "", err
}

// Get client set
func (hc *HelmClient) GetClientSet(relName, namespace string) (clientset *kubernetes.Clientset, manifest []Manifest, err error) {

	actionConfig := new(action.Configuration)
	if err = actionConfig.Init(kube.GetConfig(hc.Kubeconfig, "", namespace), namespace,
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
	manifest, err = SplitManifestYaml([]byte(res.Manifest))
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

// Update pod description information
func UpdatePodDescInfo(podDesc models.PodDescribeInfo, clientset *kubernetes.Clientset,
	label models.LabelList, namespace string) (models.PodDescribeInfo, error) {
	options := metav1.ListOptions{
		LabelSelector: label.Selector,
	}
	pods, err := clientset.CoreV1().Pods(namespace).List(context.Background(), options)
	if err != nil {
		return podDesc, err
	}
	for _, podItem := range pods.Items {
		podName := podItem.GetObjectMeta().GetName()
		pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			return podDesc, err
		}

		if ref, err := reference.GetReference(scheme.Scheme, pod); err != nil {
			log.Errorf("Unable to construct reference to '%#v': %v", pod, err)
			return podDesc, err
		} else {
			podDescInfo := GetPodDescInfo(ref, pod, clientset, podName, namespace)
			podDesc.PodDescInfo = append(podDesc.PodDescInfo, podDescInfo)
		}
	}
	return podDesc, nil
}

// Get pod description information
func GetPodDescInfo(ref *v1.ObjectReference, pod *v1.Pod, clientset *kubernetes.Clientset,
	podName, namespace string) (podDescInfo models.PodDescList) {
	ref.Kind = ""
	if _, isMirrorPod := pod.Annotations[corev1.MirrorPodAnnotationKey]; isMirrorPod {
		ref.UID = types.UID(pod.Annotations[corev1.MirrorPodAnnotationKey])
	}
	events := GetEvents(clientset, namespace, ref)
	podDescInfo.PodName = podName
	if len(events.Items) == 0 {
		podDescInfo.PodEventsList = append(podDescInfo.PodEventsList,
			"Pod is running successfully")
	}
	for _, e := range events.Items {
		podDescInfo.PodEventsList = append(podDescInfo.PodEventsList, strings.TrimSpace(e.Message))
	}
	return podDescInfo
}

// Get events
func GetEvents(clientset *kubernetes.Clientset, namespace string, ref *v1.ObjectReference) *v1.EventList {
	events, _ := clientset.CoreV1().Events(namespace).Search(scheme.Scheme, ref)
	return events
}

// Get label selector
func GetLabelSelector(manifest []Manifest) models.LabelSelector {
	var labelSelector models.LabelSelector
	var label models.LabelList
	var selector string

	for i := 0; i < len(manifest); i++ {
		if manifest[i].Kind == util.Deployment || manifest[i].Kind == util.Pod || manifest[i].Kind == util.Service {
			appName := manifest[i].Metadata.Name
			if manifest[i].Metadata.Labels.App != "" {
				appName = manifest[i].Metadata.Labels.App
			}
			if manifest[i].Kind == util.Service {
				selector = "svc=" + appName
			} else {
				selector = "app=" + appName
			}

			label.Kind = manifest[i].Kind
			label.Selector = selector
			labelSelector.Label = append(labelSelector.Label, label)
		}
	}

	return labelSelector
}

// Get JSON response
func GetJSONResponse(appInfo models.AppInfo, response map[string]string) (string, error) {
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
func GetResourcesBySelector(labelSelector models.LabelSelector, clientset *kubernetes.Clientset,
	config *rest.Config, namespace string) (appInfo models.AppInfo, response map[string]string, err error) {

	for _, label := range labelSelector.Label {
		appInfo, response, err = UpdatePodInfo(appInfo, &label, clientset, config, namespace)
		if err != nil {
			return appInfo, response, err
		}

		if label.Kind == util.Service {
			options := metav1.ListOptions{
				LabelSelector: label.Selector,
			}
			serviceInfo, err := GetServiceInfo(clientset, options, namespace)
			if err != nil {
				return appInfo, nil, err
			}
			appInfo.Services = append(appInfo.Services, serviceInfo)
		}
	}

	return appInfo, nil, nil
}

// Update pod information
func UpdatePodInfo(appInfo models.AppInfo, label *models.LabelList, clientset *kubernetes.Clientset,
	config *rest.Config,
	namespace string) (appInformation models.AppInfo, response map[string]string, err error) {
	if label.Kind == util.Pod || label.Kind == util.Deployment {
		pods, err := GetPods(clientset, namespace, label)
		if err != nil {
			return appInfo, nil, err
		}
		if len(pods.Items) == 0 {
			response = map[string]string{"status": "not running"}
			return appInfo, response, nil
		}

		podInfo, err := GetPodInfo(pods, clientset, config, namespace)
		if err != nil {
			return appInfo, nil, err
		}
		appInfo.CpuPercent = totalCpu1
		appInfo.MemPercent = totalMem1
		appInfo.Pods = append(appInfo.Pods, podInfo)
	}
	return appInfo, nil, nil
}

// Get pods
func GetPods(clientset *kubernetes.Clientset, namespace string, label *models.LabelList) (*v1.PodList, error) {
	options := metav1.ListOptions{
		LabelSelector: label.Selector,
	}
	pods, err := clientset.CoreV1().Pods(namespace).List(context.Background(), options)
	if err != nil {
		return pods, err
	}
	return pods, nil
}

// Get service information
func GetServiceInfo(clientset *kubernetes.Clientset, options metav1.ListOptions, namespace string) (serviceInfo models.ServiceInfo, err error) {
	services, err := clientset.CoreV1().Services(namespace).List(context.Background(), options)
	if err != nil {
		return serviceInfo, err
	}
	var portInfo models.PortInfo
	for _, service := range services.Items {
		serviceInfo.ServiceName = service.Name
		serviceInfo.ServiceType = string(service.Spec.Type)
		for i := range service.Spec.Ports {
			sp := &service.Spec.Ports[i]
			portInfo.Port = fmt.Sprint(sp.Port)
			if sp.TargetPort.Type == intstr.Int {
				portInfo.TargetPort = fmt.Sprint(sp.TargetPort.IntVal)
			} else {
				portInfo.TargetPort = sp.TargetPort.StrVal
			}
			portInfo.NodePort = fmt.Sprint(sp.NodePort)
			serviceInfo.Ports = append(serviceInfo.Ports, portInfo)
		}
	}
	return serviceInfo, nil
}

// Get pod information
func GetPodInfo(pods *v1.PodList, clientset *kubernetes.Clientset, config *rest.Config,
	namespace string) (podInfo models.PodInfo, err error) {
	var containerInfo models.ContainerInfo
	for _, pod := range pods.Items {
		podName := pod.GetObjectMeta().GetName()
		podMetrics, err := GetPodMetrics(config, podName, namespace)
		if err != nil {
			podInfo.PodName = podName
			podInfo.PodStatus = string(pod.Status.Phase)
			containerInfo.ContainerName = ""
			containerInfo.MetricsUsage.CpuUsage = ""
			containerInfo.MetricsUsage.MemUsage = ""
			containerInfo.MetricsUsage.DiskUsage = ""
			podInfo.Containers = append(podInfo.Containers, containerInfo)
			continue
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
func updateContainerInfo(podMetrics *v1beta1.PodMetrics, clientset *kubernetes.Clientset,
	podInfo models.PodInfo) (models.PodInfo, error) {
	var containerInfo models.ContainerInfo
	totalCpuUsage, totalMemUsage, totalDiskUsage, err := GetTotalCpuDiskMemory(clientset)
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

		cpuNum, _ := strconv.ParseUint(totalCpuUsage, 10, 32)
		cpuUsage1 := int64(cpuNum)
		cpuPercent := float64(cpu) / float64(cpuUsage1)
		totalCpu1 = totalCpu1 + cpuPercent
		memNum, _ := strconv.ParseUint(totalMemUsage, 10, 32)
		memUsage1 := int64(memNum)
		memPercent := float64(memory) / float64(memUsage1)
		totalMem1 = totalMem1 + memPercent
		podInfo.Containers = append(podInfo.Containers, containerInfo)
	}
	return podInfo, nil
}

// Get Pod metrics
func GetPodMetrics(config *rest.Config, podName, namespace string) (podMetrics *v1beta1.PodMetrics, err error) {
	mc, err := metrics.NewForConfig(config)
	if err != nil {
		return podMetrics, err
	}

	podMetrics, err = mc.MetricsV1beta1().PodMetricses(namespace).Get(context.Background(),
		podName, metav1.GetOptions{})
	if err != nil {
		return podMetrics, err
	}
	return podMetrics, nil
}

// Get total cpu disk and memory metrics
func GetTotalCpuDiskMemory(clientset *kubernetes.Clientset) (string, string, string, error) {
	var totalDiskUsage string
	var totalMemUsage string
	var totalCpuUsage string

	nodeList, err := GetNodeList(clientset)
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

// Get node list
func GetNodeList(clientset *kubernetes.Clientset) (nodeList *v1.NodeList, err error) {
	nodeList, err = clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	return nodeList, err
}

// Split manifest yaml file
func SplitManifestYaml(data []byte) (manifest []Manifest, err error) {
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
