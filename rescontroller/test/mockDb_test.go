package test

import (
	"errors"
	"reflect"
	"rescontroller/models"
	"rescontroller/util"
)

type MockDb struct {
	appInstanceRecords map[string]models.AppInfoRecord
	mecHostRecords     map[string]models.MecHost
}

func (db *MockDb) InitDatabase() error {
	panic("implement me")
}

func (db *MockDb) ReadData(data interface{}, cols ...string) (err error) {
	if cols[0] == "app_instance_id" {
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


