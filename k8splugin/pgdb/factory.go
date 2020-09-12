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

package pgdb

import (
	"errors"
	"k8splugin/conf"
	"os"
)

// Init Db adapter
func GetDbAdapter(serverConfigs *conf.ServerConfigurations) (Database, error) {
	switch serverConfigs.DbAdapter {
	case "pgDb":
		db := &PgDb{}
		err := db.InitDatabase(serverConfigs.DbSslMode)
		if err != nil {
			os.Exit(1)
		}
		return db, nil
	default:
		return nil, errors.New("no database is found")
	}
}
