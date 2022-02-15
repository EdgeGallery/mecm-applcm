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

package models

import (
	"github.com/astaxie/beego/orm"
)

// Init application info record
func init() {
	orm.RegisterModel(new(AppInstanceInfo))
	orm.RegisterModel(new(AppPackage))
}

// AppInstanceInfo info record
type AppInstanceInfo struct {
	AppInsId   string `orm:"pk"`
	HostIp     string
	WorkloadId string
	Namespace  string
}

// AppPackage info record
type AppPackage struct {
	AppPkgId     string `orm:"pk"`
	HostIp       string
	TenantId     string
	PackageId    string
	DockerImages string
}

// AppInfo Information
type AppInfo struct {
	Pods       []PodInfo     `json:"pods"`
	Services   []ServiceInfo `json:"services"`
	CpuPercent float64       `json:"cpupercent"`
	MemPercent float64       `json:"mempercent"`
}

// PodInfo Information
type PodInfo struct {
	PodStatus  string          `json:"podstatus"`
	PodName    string          `json:"podname"`
	Containers []ContainerInfo `json:"containers"`
}

// ServiceInfo Information
type ServiceInfo struct {
	ServiceName string     `json:"serviceName"`
	ServiceType string     `json:"type"`
	Ports       []PortInfo `json:"ports"`
}

// PortsList Information
type PortInfo struct {
	Port       string `json:"port"`
	TargetPort string `json:"targetPort"`
	NodePort   string `json:"nodePort"`
	Protocol   string `json:"protocol"`
	Name       string `json:"name"`
}

// ContainerInfo Information
type ContainerInfo struct {
	ContainerName string         `json:"containername"`
	MetricsUsage  ContainerStats `json:"metricsusage"`
}

// ContainerStats statistics
type ContainerStats struct {
	CpuUsage  string `json:"cpuusage"`
	MemUsage  string `json:"memusage"`
	DiskUsage string `json:"diskusage"`
}

// LabelSelector Selector
type LabelSelector struct {
	Label []LabelList
}

// LabelList Info
type LabelList struct {
	Kind     string
	Selector string
}

// PodDescribeInfo information
type PodDescribeInfo struct {
	PodDescInfo []PodDescList `json:"pods"`
}

// PodDescList info
type PodDescList struct {
	PodName       string   `json:"podName"`
	PodEventsList []string `json:"podEventsInfo"`
}

// SwImageDescriptor information
type SwImageDescriptor struct {
	Id                                 string `json:"id"`
	Name                               string `json:"name"`
	Version                            string `json:"version"`
	Checksum                           string `json:"checksum"`
	ContainerFormat                    string `json:"containerFormat"`
	DiskFormat                         string `json:"diskFormat"`
	MinDisk                            string `json:"minDisk"`
	MinRam                             string `json:"minRam"`
	Architecture                       string `json:"architecture"`
	Size                               string `json:"size"`
	SwImage                            string `json:"swImage"`
	OperatingSystem                    string `json:"operatingSystem"`
	SupportedVirtualisationEnvironment string `json:"supportedVirtualisationEnvironment"`
}

// Metric Information
type MetricInfo struct {
	CpuUsage map[string]int64 `json:"cpuusage"`
	MemUsage map[string]int64 `json:"memusage"`
}

// Return response
type ReturnResponse struct {
	Data    interface{} `json:"data"`
	RetCode int         `json:"retCode"`
	Message string      `json:"message"`
	Params  []string    `json:"params"`
}
