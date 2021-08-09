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
	"errors"
	"lcmcontroller/models"
	"lcmcontroller/util"
	"reflect"
)

type MockDb struct {
	appInstanceRecords map[string]models.AppInfoRecord
	tenantRecords      map[string]models.TenantInfoRecord
	appPackageRecords  map[string]models.AppPackageRecord
	appPackageHostRecords  map[string]models.AppPackageHostRecord
	mecHostRecords     map[string]models.MecHost

}

func (db *MockDb) InitDatabase() error {
	panic("implement me")
}

func (db *MockDb) InsertOrUpdateData(data interface{}, cols ...string) (err error) {
	if cols[0] == util.AppInsId {
		appInstance, ok := data.(*models.AppInfoRecord)
		if ok {
			db.appInstanceRecords[appInstance.AppInstanceId] = *appInstance
		}
	}
	if cols[0] == util.TenantId {
		tenant, ok := data.(*models.TenantInfoRecord)
		if ok {
			db.tenantRecords[tenant.TenantId] = *tenant
		}
	}

	if cols[0] == util.AppPkgId {
		appPackage, ok := data.(*models.AppPackageRecord)
		if ok {
			db.appPackageRecords[appPackage.AppPkgId] = *appPackage
		}
	}

	if cols[0] == util.PkgHostKey {
		appPackageHost, ok := data.(*models.AppPackageHostRecord)
		if ok {
			db.appPackageHostRecords[appPackageHost.PkgHostKey] = *appPackageHost
		}
	}

	if cols[0] == util.HostIp {
		mecHost, ok := data.(*models.MecHost)
		if ok {
			db.mecHostRecords[mecHost.MecHostId] = *mecHost
		}
	}
	return nil
}

func (db *MockDb) ReadData(data interface{}, cols ...string) (err error) {
	if cols[0] == util.AppInsId {
		appInstance, ok := data.(*models.AppInfoRecord)
		if ok {
			readAppInstance := db.appInstanceRecords[appInstance.AppInstanceId]
			if (readAppInstance == models.AppInfoRecord{}) {
				return errors.New("App Instance record not found")
			}
			appInstance.TenantId = readAppInstance.TenantId
			appInstance.MecHost = readAppInstance.MecHost
			appInstance.DeployType = readAppInstance.DeployType
			appInstance.Origin     = readAppInstance.Origin
		}
	}
	if cols[0] == util.TenantId {
		tenant, ok := data.(*models.TenantInfoRecord)
		if ok {
			readTenant := db.tenantRecords[tenant.TenantId]
			if (readTenant == models.TenantInfoRecord{}) {
				return errors.New("Tenant record not found")
			}
		}
	}
	if cols[0] == util.AppPkgId {
		appPackage, ok := data.(*models.AppPackageRecord)
		if ok {
			readAppPackage := db.appPackageRecords[appPackage.AppPkgId]
			if (reflect.DeepEqual(readAppPackage,models.AppPackageRecord{})) {
				return errors.New("App package record not found")
			}
			appPackage.TenantId = readAppPackage.TenantId
			appPackage.AppId = readAppPackage.AppId
			appPackage.PackageId = readAppPackage.PackageId
			appPackage.Origin = readAppPackage.Origin
		}
	}

	if cols[0] == util.PkgHostKey {
		appPackageHost, ok := data.(*models.AppPackageHostRecord)
		if ok {
			readAppPackageHost := db.appPackageHostRecords[appPackageHost.PkgHostKey]
			if (reflect.DeepEqual(readAppPackageHost,models.AppPackageHostRecord{})) {
				return errors.New("App package host record not found")
			}
			appPackageHost.TenantId = readAppPackageHost.TenantId
			appPackageHost.AppPkgId = readAppPackageHost.AppPkgId
			appPackageHost.HostIp = readAppPackageHost.HostIp
			appPackageHost.Status = readAppPackageHost.Status
		}
	}

	if cols[0] == util.HostIp {
		mecHost, ok := data.(*models.MecHost)
		if ok {
			readMecHost := db.mecHostRecords[mecHost.MecHostId]
			if (reflect.DeepEqual(readMecHost,models.MecHost{})) {
				return errors.New("MEC host record not found")
			}
			mecHost.MecHostId = readMecHost.MecHostId
			mecHost.MechostIp = readMecHost.MechostIp
			mecHost.MechostName = readMecHost.MechostName
			mecHost.Vim = readMecHost.Vim
			mecHost.Origin     = readMecHost.Origin
		}
	}
	if cols[0] == "app_pkg_name" {
		return errors.New("record not found")
	}
	return nil
}

func (db *MockDb) DeleteData(data interface{}, cols ...string) (err error) {
	if cols[0] == util.AppInsId {
		appInstance, ok := data.(*models.AppInfoRecord)
		if ok {
			readAppInstance := db.appInstanceRecords[appInstance.AppInstanceId]
			if (readAppInstance == models.AppInfoRecord{}) {
				return errors.New("App Instance record not found")
			}
			delete(db.appInstanceRecords, readAppInstance.AppInstanceId)
		}
	}
	if cols[0] == util.TenantId {
		tenant, ok := data.(*models.TenantInfoRecord)
		if ok {
			readTenant := db.tenantRecords[tenant.TenantId]
			if (readTenant == models.TenantInfoRecord{}) {
				return errors.New("Tenant record not found")
			}
			delete(db.tenantRecords, readTenant.TenantId)
		}
	}
	if cols[0] == util.AppPkgId {
		appPackage, ok := data.(*models.AppPackageRecord)
		if ok {
			readAppPackage := db.appPackageRecords[appPackage.AppPkgId]
			if (reflect.DeepEqual(readAppPackage,models.AppPackageRecord{})) {
				return errors.New("App Package record not found")
			}
			delete(db.appPackageRecords, readAppPackage.AppPkgId)
		}
	}

	if cols[0] == util.PkgHostKey {
		appPackageHost, ok := data.(*models.AppPackageHostRecord)
		if ok {
			readAppPackageHost := db.appPackageHostRecords[appPackageHost.PkgHostKey]
			if (reflect.DeepEqual(readAppPackageHost,models.AppPackageRecord{})) {
				return errors.New("App Package host record not found")
			}
			delete(db.appPackageRecords, readAppPackageHost.PkgHostKey)
		}
	}

	if cols[0] == util.HostIp {
		mecHost, ok := data.(*models.MecHost)
		if ok {
			readMecHost := db.mecHostRecords[mecHost.MecHostId]
			if (reflect.DeepEqual(readMecHost,models.MecHost{})) {
				return errors.New("App Package record not found")
			}
			delete(db.mecHostRecords, readMecHost.MecHostId)
		}
	}
	return nil
}

func (db *MockDb) QueryCount(tableName string) (int64, error) {
	return 0, nil
}

func (db *MockDb) QueryCountForTable(tableName, fieldName, fieldValue string) (int64, error) {
	if tableName == "app_info_record" {
		var count int64
		for _, _ = range db.appInstanceRecords {
			count++
		}
		return count, nil
	}
	return 0, nil
}

func (db *MockDb) QueryTable(tableName string, container interface{}, field string, container1 ...interface{}) (int64, error) {
	if tableName == "app_info_record" {
		for _, appInfoRec := range db.appInstanceRecords {
			container = appInfoRec
		}

		return 1, nil
	}

	if tableName == util.AppPackageRecordId {
		for _, appPkgRec := range db.appPackageRecords {
			container = appPkgRec
		}
		return 1, nil
	}
	return 0, nil
}

func (db *MockDb) LoadRelated(md interface{}, name string) (int64, error) {
	return 0, nil
}

