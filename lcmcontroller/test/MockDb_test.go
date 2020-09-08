package test

import (
	"errors"
	"lcmcontroller/models"
	"lcmcontroller/util"
)

type MockDb struct {
	appInstanceRecords map[string]models.AppInfoRecord
	tenantRecords      map[string]models.TenantInfoRecord
}

func (db *MockDb) InitDatabase() error {
	panic("implement me")
}

func (db *MockDb) InsertOrUpdateData(data interface{}, cols ...string) (err error) {
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

func (db *MockDb) ReadData(data interface{}, cols ...string) (err error) {
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

func (db *MockDb) DeleteData(data interface{}, cols ...string) (err error) {
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

func (db *MockDb) QueryCount(tableName string) (int64, error) {
	return 0, nil
}

func (db *MockDb) QueryCountForAppInfo(tableName, fieldName, fieldValue string) (int64, error) {
	return 0, nil
}
