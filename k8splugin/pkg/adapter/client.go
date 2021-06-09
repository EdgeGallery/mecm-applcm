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

package adapter

import (
	"k8splugin/models"
	"k8splugin/pgdb"
)

// Client APIs
type ClientIntf interface {
	Deploy(appPkgRecord *models.AppPackage, appInsId string, ak string, sk string, db pgdb.Database) (string, string, error)
	UnDeploy(relName, namespace string) error
	Query(relName, namespace string) (string, error)
	WorkloadEvents(relName, namespace string) (string, error)
}
