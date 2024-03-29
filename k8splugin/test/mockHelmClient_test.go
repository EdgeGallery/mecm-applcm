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
	"k8splugin/models"
	"k8splugin/pgdb"
)

// Helm client
type mockedHelmClient struct {
}

func (hc *mockedHelmClient) Deploy(appPkgRec *models.AppPackage, appInsId string, ak string, sk string, db pgdb.Database) (string, string, error) {
	return "testRelease", "default", nil
}

func (hc *mockedHelmClient) UnDeploy(relName, namespace string) error {
	return nil
}

func (hc *mockedHelmClient) Query(relName, namespace string) (string, error) {
	// Output to be checked
	return outputSuccess, nil
}


func (hc *mockedHelmClient) QueryKPI() (string, error) {
	// Output to be checked
	return outputSuccess, nil
}

func (hc *mockedHelmClient) WorkloadEvents(relName, namespace string) (string, error) {
	// Output to be checked
	return outputSuccess, nil
}

