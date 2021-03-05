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
	"time"
)

// Init application info record
func init() {
	orm.RegisterModel(new(AppInfoRecord))
	orm.RegisterModel(new(TenantInfoRecord))
	orm.RegisterModel(new(MecHost))
	orm.RegisterModel(new(MecHwCapability))
}

// MEC host record
type MecHost struct {
	MechostId string `orm:"pk"`
	CreateTime time.Time `orm:"auto_now_add;type(datetime)"`
	MechostIp string
	MechostName string
	ZipCode string
	City string;
	Address string
	Affinity string
	UserName string
	ApplcmIp string
	AppRuleIp string
	ConfigUploadStatus string
	Coordinates string
	Vim string
	Hwcapabilities []*MecHwCapability `orm:"reverse(many)"` // reverse relationship of fk
	// Association with AppInfoRecord is pending
}

// MEC host hardware capabilities
type MecHwCapability struct {
	MecCapabilityId string `orm:"pk"`
	CreateTime time.Time `orm:"auto_now_add;type(datetime)"`
	HwType string
	HwVendor string
	HwModel string
	MecHost *MecHost `orm:"rel(fk)"` // RelForeignKey relation
}

// Application info record
type AppInfoRecord struct {
	AppInsId   string `orm:"pk"`
	HostIp     string
	DeployType string
	TenantId   string
	PackageId  string
}

// Tenant info record
type TenantInfoRecord struct {
	TenantId string `orm:"pk"`
}

// Metric Information
type MetricInfo struct {
	CpuUsage  map[string]interface{} `json:"cpuusage"`
	MemUsage  map[string]interface{}`json:"memusage"`
	DiskUsage  map[string]interface{}`json:"diskusage"`
}

// Kpi Information
type KpiModel struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric struct {
			} `json:"metric"`
			Value []interface{} `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

// CreateVimRequest record
type CreateVimRequest struct {
	VmId string `json:"vmId"`
}
