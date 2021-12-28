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
	orm.RegisterModel(new(AppPackageRecord))
	orm.RegisterModel(new(AppPackageHostRecord))
	orm.RegisterModel(new(AppPackageStaleRec))
	orm.RegisterModel(new(AppPackageHostStaleRec))
	orm.RegisterModel(new(EdgeAuthenticateRec))
	orm.RegisterModel(new(AppPackageStatusRecord))
	orm.RegisterModel(new(AppPackageHostStatusRecord))
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
	TenantId           string
	ConfigUploadStatus string
	Coordinates        string
	Vim                string
	Origin             string
	SyncStatus         bool
	Public             string
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
	AppInstanceId string    `orm:"pk"`
	CreateTime    time.Time `orm:"auto_now_add;type(datetime)"`
	MecHost       string
	DeployType    string
	TenantId      string
	AppPackageId  string
	AppName       string
	Origin        string
	SyncStatus    bool
	MecHostRec    *MecHost `orm:"rel(fk)"` // RelForeignKey relation
}


// Application info record
type AppInfoRec struct {
	AppInstanceId string    `orm:"pk" json:"appInstanceId"`
	CreateTime    time.Time `orm:"auto_now_add;type(datetime)" json:"createTime"`
	MecHost        string    `json:"mecHost"`
	DeployType    string	`json:"deployType"`
	TenantId      string	`json:"tenantId"`
	AppPackageId  string	`json:"appPackageId"`
	AppName       string	`json:"appName"`
	Origin        string	`json:"origin"`
	SyncStatus    bool      `json:"syncStatus"`
}

// App instance updated records
type AppInfoUpdatedRecords struct {
	AppInfoUpdatedRecs []AppInfoRec `json:"appInstanceUpdatedRecs"`
}

// App instance stale records
type AppInstanceStaleRecords struct {
	AppInstanceStaleRecs []AppInstanceStaleRec `json:"appInstanceDeletedRecs"`
}

// Application package record
type AppPackageRecordInfo struct {
	AppPkgId       string   `json:"appPkgId"`
	AppPkgName     string   `json:"appPkgName"`
	AppPkgVersion  string   `json:"appPkgVersion"`
	AppPkgPath     string   `json:"appPkgPath"`
	AppProvider    string   `json:"appProvider"`
	AppPkgDesc     string   `json:"appPkgDesc"`
	AppPkgAffinity string   `json:"appPkgAffinity"`
	AppIconUrl     string   `json:"appIconUrl"`
	CreatedTime    string   `json:"createdTime"`
	ModifiedTime   string   `json:"modifiedTime"`
	AppId          string   `json:"appId"`
	TenantId       string   `json:"tenantId"`
	PackageId      string   `json:"packageId"`
	Origin         string   `json:"origin"`
	SyncStatus     bool     `json:"syncStatus"`
	MecHostInfo []AppPackageHostRecordInfo       `json:"mecHostInfo"`
}

// App package host record
type AppPackageHostRecordInfo struct {
	PkgHostKey             string    `json:"pkgHostKey"`
	HostIp                 string    `json:"hostIp"`
	AppPkgId               string    `json:"appPkgId"`
	Status                 string    `json:"status"`
	TenantId               string    `json:"tenantId"`
	Error                  string    `json:"error"`
	Origin                 string    `json:"origin"`
	SyncStatus             bool      `json:"syncStatus"`
}

// Application package record
type AppPackageRecord struct {
	AppPkgId       string `orm:"pk"`
	AppPkgName     string
	AppPkgVersion  string
	AppPkgPath     string
	AppProvider    string
	AppPkgDesc     string
	AppPkgAffinity string
	AppIconUrl     string
	CreatedTime    string
	ModifiedTime   string
	AppId          string
	TenantId       string
	PackageId      string
	Origin         string
	SyncStatus     bool
	MecHostInfo    []*AppPackageHostRecord `orm:"reverse(many);on_delete(set_null)"` // reverse relationship of fk
}

// App package host record
type AppPackageHostRecord struct {
	PkgHostKey string `orm:"pk"`
	HostIp     string
	AppPkgId   string
	Status     string
	TenantId   string
	Error      string
	Origin     string
	SyncStatus bool
	AppPackage *AppPackageRecord `orm:"rel(fk)"` // RelForeignKey relation
}

// Mec host updated records
type AppPackagesUpdatedRecords struct {
	AppPackagesUpdatedRecs []AppPackageRecordInfo `json:"appPackageRecord"`
}

// App package host stale records
type AppDistPkgHostStaleRecords struct {
	AppPackageStaleRecs []AppPackageStaleRec `json:"appPackageStaleRec"`
	AppPackageHostStaleRec []AppPackageHostStaleRec `json:"appPackageHostStaleRec"`
}

// App package key information
type AppPackageHostStaleRec struct {
	PackageId      string `orm:"pk" json:"packageId"`
	TenantId        string `json:"tenantId"`
	HostIp          string `json:"hostIp"`
}

// App package key information
type AppPackageStaleRec struct {
	AppPkgId      string `orm:"pk" json:"appPackageId"`
	TenantId      string `json:"tenantId"`
}

// Application package status record
type AppPackageStatusRecord struct {
	AppPkgName             string `json:"appPkgName"`
	AppPkgVersion          string `json:"appPkgVersion"`
	AppProvider            string `json:"appProvider"`
	AppPkgDesc             string `json:"appPkgDesc"`
	AppPkgAffinity         string `json:"appPkgAffinity"`
	AppId                  string `json:"appId"`
	PackageId              string  `orm:"pk" json:"packageId"`
	AppIconUrl             string `json:"appIconUrl"`
	CreatedTime            string `json:"createdTime"`
	ModifiedTime           string `json:"modifiedTime"`
	MecHostInfo []*AppPackageHostStatusRecord `orm:"reverse(many);on_delete(set_null)" json:"mecHostInfo"`
}

// Application package host status record
type AppPackageHostStatusRecord struct {
	HostIp                 string `orm:"pk" json:"hostIp"`
	Status                 string `json:"status"`
	Error                  string `json:"error"`
	AppPackageStatus *AppPackageStatusRecord `orm:"rel(fk)"` // RelForeignKey relation
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
	MechostIp          string              `json:"mechostIp"`
	MechostName        string              `json:"mechostName"`
	ZipCode            string              `json:"zipCode"`
	City               string              `json:"city"`
	Address            string              `json:"address"`
	Affinity           string              `json:"affinity"`
	TenantId           string              `json:"tenantId"`
	ConfigUploadStatus string              `json:"configUploadStatus"`
	Coordinates        string              `json:"coordinates"`
	Vim                string              `json:"vim"`
	Origin             string              `json:"origin"`
	Public             string              `json:"public"`
	Hwcapabilities     []MecHwCapabilities `json:"hwcapabilities"`
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

// App instance stale records
type AppInstanceStaleRec struct {
	AppInstanceId string `orm:"pk" json:"appInstanceId"`
	TenantId      string `json:"tenantId"`
}

// Mec host stale records
type MecHostStaleRecords struct {
	MecHostStaleRecs []MecHostStaleRec `json:"mecHostStaleRecs"`
}

// Mec host stale records
type MecHostStaleRec struct {
	MecHostId string `orm:"pk" json:"mechostIp"`
}

// Application package distribute request
type DistributeRequest struct {
	HostIp []string `json:"hostIp"`
	Origin string `json:"origin"`
}

// Application package instantiation request
type InstantiateRequest struct {
	HostIp     string            `json:"hostIp"`
	PackageId  string            `json:"packageId"`
	AppName    string            `json:"appName"`
	Origin     string            `json:"origin"`
	Parameters map[string]string `json:"parameters"`
	AkSkLcmGen bool              `json:"akSkGen"`
}

//Vnf Data
type VnfData struct {
	VnfdMetaFileVersion int     `json:"VNFD-Meta-File-Version"`
	CsarVersion         float64 `json:"CSAR-Version"`
	CreatedBy           string  `json:"Created-by"`
	EntryDefinitions    string  `json:"Entry-Definitions"`
	Name                string  `json:"Name"`
	ContentType         string  `json:"Content-Type"`
}

// App package details info
type AppPkgDetails struct {
	App_product_name   string `json:"app_product_name"`
	App_provider_id string `json:"app_provider_id"`
	App_package_version  string `json:"app_package_version"`
	App_release_data_time   string `json:"app_release_data_time"`
	App_type string `json:"app_type"`
	App_class string `json:"app_class"`
	App_package_description  string `json:"app_package_description"`
}

// App package response info
type AppPackageResponse struct {
	AppId     string `json:"appId"`
	PackageId string `json:"packageId"`
}

type ReturnResponse struct {
	Data    interface{} `json:"data"`
	RetCode int         `json:"retCode"`
	Message string      `json:"message"`
	Params  []string    `json:"params"`
}

// AppInfoParams info record for Instantiate
type AppInfoParams struct {
	AppInstanceId string
	MecHost       string
	DeployType    string
	TenantId      string
	ConfitTenantId string
	AppPackageId  string
	AppName       string
	Origin        string
	SyncStatus    bool
	ClientIP      string
	AccessToken   string
	Vim           string
}

// Edge Authentication Info
type EdgeAuthenticateRec struct {
	AuthenticateId string `orm:"pk" json:"authenticate_id"`
	Name           string `json:"name"`
	Key            string `json:"key"`
}
