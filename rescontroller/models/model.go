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
	"rescontroller/internal/internal_resourcemanager"
	"time"
)

// Init application info record
func init() {
	orm.RegisterModel(new(EdgeAuthenticateRec))
	orm.RegisterModel(new(AppInfoRecord))
	orm.RegisterModel(new(MecHost))
	orm.RegisterModel(new(MecHwCapability))
}

type ReturnResponse struct {
	Data    interface{} `json:"data"`
	RetCode int         `json:"retCode"`
	Message string      `json:"message"`
	Params  []string    `json:"params"`
}

// Edge Authentication Info
type EdgeAuthenticateRec struct {
	AuthenticateId string `orm:"pk" json:"authenticate_id"`
	Name           string `json:"name"`
	Key            string `json:"key"`
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

// Flavor info
type Flavor struct {
	Name       string   `json:"name"`
	Vcpus      int32    `json:"vcpus"`
	Ram        int32    `json:"ram"`
	Disk       int32    `json:"disk"`
	Swap       int32    `json:"swap"`
	ExtraSpecs map[string]string `json:"extraSpecs"`
}

// Security group info
type SecurityGroup struct {
	Name string `json:"name"`
}

// Security group rules
type SecurityGroupRules struct {
	Securitygroupid string `json:"securityGroupId"`
	Direction       string `json:"direction"`
	Protocol        string `json:"protocol"`
	Ethertype       string `json:"ethertype"`
	PortRangeMin    int32  `json:"port_range_min"`
	PortRangeMax    int32  `json:"port_range_max"`
	Remoteipprefix  string `json:"remoteIpPrefix"`
	RemoteGroupID   string `json:"remote_group_id"`
}

// Image info
type Image struct {
	Name            string `json:"name"`
	Containerformat string `json:"containerFormat"`
	Diskformat      string `json:"diskFormat"`
	Minram          int32    `json:"minRam"`
	Mindisk         int32    `json:"minDisk"`
	Properties      map[string]string `json:"properties"`
}

// Import image info
type ImportImage struct {
	Imageid     string `json:"imageId"`
	Resourceuri string `json:"resourceUri"`
}

// Server Info
type Server struct {
	Name             string `json:"name"`
	Flavor           string `json:"flavor"`
	Image            string `json:"image"`
	Imageref         string `json:"imageRef"`
	Availabilityzone string `json:"availabilityZone"`
	UserData         string `json:"user_data"`
	Configdrive      bool `json:"configDrive"`
	Securitygroups   []struct {
		Name string `json:"name"`
	} `json:"securityGroups"`
	Network []*internal_resourcemanager.CreateVmRequest_Server_Network `json:"netWork"`
}

// Operate Server
type OperateServer struct {
	Action      string             `json:"action"`
	Reboot      string             `json:"reboot"`
	Createimage struct {
		Name     string            `json:"name"`
		Metadata map[string]string `json:"metadata"`
	} `json:"createImage"`
}

// Network info
type Network struct {
	Name                    string                                                           `json:"name"`
	Adminstateup            bool                                                             `json:"adminStateUp"`
	Mtu                     int32                                                            `json:"mtu"`
	Providernetworktype     string                                                           `json:"providerNetworkType"`
	Providerphysicalnetwork string                                                           `json:"providerPhysicalNetwork"`
	Providersegmentationid  int32                                                            `json:"providerSegmentationId"`
	Qospolicyid             string                                                           `json:"qosPolicyId"`
	Routerexternal          bool                                                             `json:"routerExternal"`
	Segments                []*internal_resourcemanager.CreateNetworkRequest_Network_Segment `json:"segments"`
	Shared                  bool                                                             `json:"shared"`
	Isdefault               bool                                                             `json:"isDefault"`
	Subnets                 []*internal_resourcemanager.CreateNetworkRequest_Network_Subnet  `json:"subnets"`
}
