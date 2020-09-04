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
)

const (
	configPath = "/usr/app/conf"
)

// Start k8splugin application
func main() {
	log.Info("Starting k8s plugin server")

	config, err := util.GetConfiguration(configPath)

	if err != nil {
		log.Errorf("Exiting system...")
		return
	}

	// Create GRPC server
	serverConfig := server.ServerGRPCConfig{Address: config.Server.Httpsaddr, Port: config.Server.Serverport,
		ServerConfig: &config.Server}
	grpcServer := server.NewServerGRPC(serverConfig)

	// Start listening
	err = grpcServer.Listen()
	if err != nil {
		log.Errorf("Exiting system...")
		return
	}
}
