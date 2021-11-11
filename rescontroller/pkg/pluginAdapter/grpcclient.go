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
	"crypto/tls"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	resservice "rescontroller/internal/resservice"
	"rescontroller/models"
	"rescontroller/util"
)

// GRPC client to different GRPC supported plugins
type ClientGRPC struct {
	conn                   *grpc.ClientConn
	flavorClient           resservice.FlavorManagerClient
	networkClient          resservice.NetworkManagerClient
	securityGroupClient    resservice.SecurityGroupManagerClient
	vmImageClient          resservice.VmImageMangerClient
	vmClient               resservice.VmManagerClient
	chunkSize   int
}

// GRPC client configuration
type ClientGRPCConfig struct {
	Address         string
	ChunkSize       int
	RootCertificate string
}

var tlsConfig *tls.Config

// Create a GRPC client
func NewClientGRPC(cfg ClientGRPCConfig) (c *ClientGRPC, err error) {

	var (
		grpcOpts []grpc.DialOption
		conn     *grpc.ClientConn
	)

	if util.GetAppConfig("client_ssl_enable") == "true" {
		if util.ReadTlsCfg {
			tlsConfig, err = util.TLSConfig(cfg.RootCertificate)
			if err != nil {
				log.Error("failed to get TLS configuration with error")
				return nil, err
			}
			util.ReadTlsCfg = false
		}
		creds := credentials.NewTLS(tlsConfig)
		size := 1024 * 1024 * 24
		grpcOpts = append(grpcOpts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(size)))
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(creds))
		// Create a connection with the TLS credentials
		conn, err = grpc.Dial(cfg.Address, grpcOpts...)
	} else {
		// Create non TLS connection
		grpcOpts = append(grpcOpts, grpc.WithInsecure())
		conn, err = grpc.Dial(cfg.Address, grpcOpts...)
	}

	if err != nil {
		log.Error("failed to dial GRPC connection for address")
		return c, err
	}

	return &ClientGRPC{chunkSize: cfg.ChunkSize, conn: conn, flavorClient: resservice.NewFlavorManagerClient(conn),
		networkClient: resservice.NewNetworkManagerClient(conn), securityGroupClient: resservice.NewSecurityGroupManagerClient(conn),
		vmImageClient: resservice.NewVmImageMangerClient(conn), vmClient: resservice.NewVmManagerClient(conn)}, nil
}

// Create flavor
func (c *ClientGRPC) CreateFlavor(ctx context.Context, flavor models.Flavor, hostIp, accessToken, tenantId string) (response string, error error) {
	reqFlavor := &resservice.CreateFlavorRequest_Flavor{
		Name:  flavor.Name,
		Vcpus: flavor.Vcpus,
		Ram:   flavor.Ram,
		Disk:  flavor.Disk,
		Swap:  flavor.Swap,
		ExtraSpecs: flavor.ExtraSpecs,
	}
	req := &resservice.CreateFlavorRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		Flavor:        reqFlavor,
	}
	resp, err := c.flavorClient.CreateFlavor(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Query flavor
func (c *ClientGRPC) QueryFlavor(ctx context.Context, hostIp, accessToken, tenantId, flavorId string) (response string, error error) {
	req := &resservice.QueryFlavorRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		FlavorId:      flavorId,
	}
	resp, err := c.flavorClient.QueryFlavor(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Delete flavor
func (c *ClientGRPC) DeleteFlavor(ctx context.Context, hostIp, accessToken, tenantId, flavorId string) (response string, error error) {
	req := &resservice.DeleteFlavorRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		FlavorId:      flavorId,
	}
	resp, err := c.flavorClient.DeleteFlavor(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}