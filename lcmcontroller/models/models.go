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
	orm.RegisterModel(new(AppInstanceStaleRec))
	orm.RegisterModel(new(MecHostStaleRec))
}

// MEC host record
type MecHost struct {
	MecHostId          string    `orm:"pk"`
	CreateTime         time.Time `orm:"auto_now_add;type(datetime)"`
	MechostIp          string
	MechostName        string
	ZipCode            string
	City               string
	Address            string
	Affinity           string
	UserName           string
	ConfigUploadStatus string
	Coordinates        string
	Vim                string
	Origin             string
	SyncStatus         bool
	Hwcapabilities     []*MecHwCapability `orm:"reverse(many);on_delete(set_null)"` // reverse relationship of fk
	AppInfoRecords     []*AppInfoRecord   `orm:"reverse(many);on_delete(set_null)"` // reverse relationship of fk
}

// MEC host hardware capabilities
type MecHwCapability struct {
	MecCapabilityId string    `orm:"pk"`
	CreateTime      time.Time `orm:"auto_now_add;type(datetime)"`
	HwType          string
	HwVendor        string
	HwModel         string
	MecHost         *MecHost `orm:"rel(fk)"` // RelForeignKey relation
}

// Application info record
type AppInfoRecord struct {
	AppInsId   string    `orm:"pk"`
	CreateTime time.Time `orm:"auto_now_add;type(datetime)"`
	HostIp     string
	DeployType string
	TenantId   string
	PackageId  string
	AppName    string
	Origin     string
	SyncStatus bool
	MecHost    *MecHost `orm:"rel(fk)"` // RelForeignKey relation
}

// Tenant info record
type TenantInfoRecord struct {
	TenantId string `orm:"pk"`
}

// Metric Information
type MetricInfo struct {
	CpuUsage  map[string]interface{} `json:"cpuusage"`
	MemUsage  map[string]interface{} `json:"memusage"`
	DiskUsage map[string]interface{} `json:"diskusage"`
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

// Mec host updated records
type MecHostUpdatedRecords struct {
	MecHostUpdatedRecs []MecHostInfo `json:"mecHostUpdatedRecs"`
}

// Mec host information
type MecHostInfo struct {
	MechostIp      string              `json:"mechostIp"`
	MechostName    string              `json:"mechostName"`
	ZipCode        string              `json:"zipCode"`
	City           string              `json:"city"`
	Address        string              `json:"address"`
	Affinity       string              `json:"affinity"`
	UserName       string              `json:"userName"`
	Coordinates    string              `json:"coordinates"`
	Vim            string              `json:"vim"`
	Hwcapabilities []MecHwCapabilities `json:"hwcapabilities"`
}

// Mec hardware capabilities
type MecHwCapabilities struct {
	HwType   string `json:"hwType"`
	HwVendor string `json:"hwVendor"`
	HwModel  string `json:"hwModel"`
}

// App instances information
type AppInstancesInfo struct {
	AppInstances string `json:"appInstances"`
}

// App instances key information
type AppInstanceStaleRec struct {
	AppInsId string `orm:"pk"`
	TenantId string
}

// Mec host stale records
type MecHostStaleRecords struct {
	MecHostStaleRecs []MecHostStaleRec `json:"mecHostStaleRecs"`
}

// App instances key information
type MecHostStaleRec struct {
	MecHostIp string `orm:"pk" json:"mechostIp"`
}
