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
}

// Application instance info record
type AppInstanceInfo struct {
	AppInsId   string `orm:"pk"`
	HostIp     string
	WorkloadId string
}

// Application Information
type AppInfo struct {
	Pods []PodInfo `json:"pods"`
}

// Pod Information
type PodInfo struct {
	PodStatus  string          `json:"podstatus"`
	PodName    string          `json:"podname"`
	Containers []ContainerInfo `json:"containers"`
}

// Container Information
type ContainerInfo struct {
	ContainerName string         `json:"containername"`
	MetricsUsage  ContainerStats `json:"metricsusage"`
}

// Container statistics
type ContainerStats struct {
	CpuUsage  string `json:"cpuusage"`
	MemUsage  string `json:"memusage"`
	DiskUsage string `json:"diskusage"`
}

// Label Selector
type LabelSelector struct {
	Label []Label
}

// Label Info
type Label struct {
	Kind     string
	Selector string
}

// Pod information
type PodDescribeInfo struct {
	PodDescInfo []PodDescInfo `json:"podDescInfo"`
}

// Pod Description Info
type PodDescInfo struct {
	PodName     string `json:"podName"`
	PodEventsInfo []string `json:"podEventsInfo"`
}
