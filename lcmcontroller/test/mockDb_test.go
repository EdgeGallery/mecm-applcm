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
	"github.com/astaxie/beego/orm"
	"lcmcontroller/models"
	"lcmcontroller/util"
)

type mockDb struct {
	appInstanceRecords map[string]models.AppInfoRecord
	tenantRecords      map[string]models.TenantInfoRecord
}

func (db *mockDb) InitDatabase() error {
	panic("implement me")
}

func (db *mockDb) InsertOrUpdateData(data interface{}, cols ...string) (err error) {
	if cols[0] == util.AppInsId {
		appInstance, ok := data.(*models.AppInfoRecord)
		if ok {
			db.appInstanceRecords[appInstance.AppInsId] = *appInstance
		}
	}
	if cols[0] == util.TenantId {
		tenant, ok := data.(*models.TenantInfoRecord)
		if ok {
			db.tenantRecords[tenant.TenantId] = *tenant
		}
	}
	return nil
}

func (db *mockDb) ReadData(data interface{}, cols ...string) (err error) {
	if cols[0] == util.AppInsId {
		appInstance, ok := data.(*models.AppInfoRecord)
		if ok {
			readAppInstance := db.appInstanceRecords[appInstance.AppInsId]
			if (readAppInstance == models.AppInfoRecord{}) {
				return errors.New("App Instance record not found")
			}
			appInstance.TenantId = readAppInstance.TenantId
			appInstance.HostIp = readAppInstance.HostIp
			appInstance.DeployType = readAppInstance.DeployType
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
	return nil
}

func (db *mockDb) DeleteData(data interface{}, cols ...string) (err error) {
	if cols[0] == util.AppInsId {
		appInstance, ok := data.(*models.AppInfoRecord)
		if ok {
			readAppInstance := db.appInstanceRecords[appInstance.AppInsId]
			if (readAppInstance == models.AppInfoRecord{}) {
				return errors.New("App Instance record not found")
			}
			delete(db.appInstanceRecords, readAppInstance.AppInsId)
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
	return nil
}

func (db *mockDb) QueryCount(tableName string) (int64, error) {
	return 0, nil
}

func (db *mockDb) QueryCountForAppInfo(tableName, fieldName, fieldValue string) (int64, error) {
	return 0, nil
}

func (db *mockDb) QueryTable(tableName string) orm.QuerySeter {
	return nil
}

func (db *mockDb) InsertMulti(bulk int, mds interface{}) (int64, error) {
	return 0, nil
}
