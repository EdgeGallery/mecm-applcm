/*
 * Copyright 2021 Huawei Technologies Co., Ltd.
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

package pluginAdapter

import (
	"errors"
)

const (
	chunkSize      = 1024
	clientProtocol = "grpc"
)

// Get client based on client protocol type
func GetClient(pluginInfo string) (client ClientIntf, err error) {
	// To support testability requirement client protocol is not taken from config currently.
	switch clientProtocol {
	case "grpc":
		clientConfig := ClientGRPCConfig{Address: pluginInfo, ChunkSize: chunkSize,
			RootCertificate: "HTTPSClientCA"}
		var client, err = NewClientGRPC(clientConfig)
		if err != nil {
			return nil, err
		}
		return client, nil
	default:
		return nil, errors.New("no client is found")
	}
}
