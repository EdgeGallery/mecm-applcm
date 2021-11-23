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
	"errors"
	log "github.com/sirupsen/logrus"
	"k8splugin/util"
	"os"
)


// Get client based on deploy type
func GetClient(deployType string, tenantId string, hostIp string) (client ClientIntf, err error) {
	switch deployType {
	case util.DeployType:
		hc, err := NewHelmClient(tenantId, hostIp)
		if os.IsNotExist(err) {
			log.Error(util.KubeConfigNotFound)
			return nil, errors.New(util.KubeConfigNotFound)
		}
		return hc, nil
	default:
		return nil, errors.New("no client is found")
	}
}

