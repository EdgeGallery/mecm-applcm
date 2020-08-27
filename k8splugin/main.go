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

package main

import (
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	_ "k8splugin/config"
	_ "k8splugin/models"
	_ "k8splugin/pgdb"
	"k8splugin/pkg/server"
	"k8splugin/util"
	"os"
	"strconv"
)

// Variables to be defined in deployment file
var (
	serverPort  = os.Getenv("HELM_PLUGIN_PORT")
	certificate = os.Getenv("CERTIFICATE_PATH")
	key         = os.Getenv("KEY_PATH")
)

// Start k8splugin application
func main() {
	log.Info("Started k8s plugin server")

	// Create GRPC server
	serPortValid, validateSerPortErr := util.ValidateServerPort(serverPort)
	if validateSerPortErr != nil || !serPortValid {
		log.Fatalf("invalid port: %v", validateSerPortErr)
	}
	sp, err := strconv.Atoi(serverPort)
	serverConfig := server.ServerGRPCConfig{Certificate: certificate, Port: sp, Key: key}
	grpcServer := server.NewServerGRPC(serverConfig)

	// Start listening
	err = grpcServer.Listen()
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
}
