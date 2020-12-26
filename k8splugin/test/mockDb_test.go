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
	"k8splugin/models"
	"k8splugin/util"
)

type mockK8sPluginDb struct {
	appInstanceRecords map[string]models.AppInstanceInfo
}

func (db *mockK8sPluginDb) InitDatabase(_ string) error {
	panic("implement me")
}

func (db *mockK8sPluginDb) InsertOrUpdateData(data interface{}, cols ...string) (err error) {
	if cols[0] == util.AppInsId {
		appInstance, ok := data.(*models.AppInstanceInfo)
		if ok {
			db.appInstanceRecords[appInstance.AppInsId] = *appInstance
		}
	}
	return nil
}

func (db *mockK8sPluginDb) ReadData(data interface{}, cols ...string) (err error) {
	if cols[0] == util.AppInsId {
		appInstance, ok := data.(*models.AppInstanceInfo)
		if ok {
			readAppInstance := db.appInstanceRecords[appInstance.AppInsId]
			if (readAppInstance == models.AppInstanceInfo{}) {
				return errors.New("App Instance record not found")
			}
			appInstance.WorkloadId = readAppInstance.WorkloadId
			appInstance.HostIp = readAppInstance.HostIp
		}
	}
	if cols[0] == "workload_id" {
		return errors.New("App Instance record not found")
	}
	return nil
}

func (db *mockK8sPluginDb) DeleteData(data interface{}, cols ...string) (err error) {
	return nil
}

