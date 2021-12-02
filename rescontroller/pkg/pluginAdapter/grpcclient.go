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
	resservice "rescontroller/internal/internal_resourcemanager"
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
		networkClient: resservice.NewNetworkManagerClient(conn),
		securityGroupClient: resservice.NewSecurityGroupManagerClient(conn),
		vmImageClient: resservice.NewVmImageMangerClient(conn), vmClient: resservice.NewVmManagerClient(conn)}, nil
}

// Create flavor
func (c *ClientGRPC) CreateFlavor(ctx context.Context, flavor models.Flavor, hostIp, accessToken,
	tenantId string) (response string, error error) {
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
	return resp.Status, err
}

// Query flavor
func (c *ClientGRPC) QueryFlavor(ctx context.Context, hostIp, accessToken, tenantId,
	flavorId string) (response string, error error) {
	req := &resservice.QueryFlavorRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		FlavorId:      flavorId,
	}
	resp, err := c.flavorClient.QueryFlavor(ctx, req)
	if err != nil {
		log.Error("Error ", err.Error())
		return "", err
	}
	return resp.Response, err
}

// Delete flavor
func (c *ClientGRPC) DeleteFlavor(ctx context.Context, hostIp, accessToken, tenantId,
	flavorId string) (response string, error error) {
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
	return resp.Status, err
}

// Create security group
func (c *ClientGRPC) CreateSecurityGroup(ctx context.Context, securityGroup models.SecurityGroup,
	hostIp, accessToken, tenantId string) (response string, error error) {

	secGroup := &resservice.CreateSecurityGroupRequest_SecurityGroup{
		Name: securityGroup.Name,
	}
	req := &resservice.CreateSecurityGroupRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		SecurityGroup: secGroup,
	}
	resp, err := c.securityGroupClient.CreateSecurityGroup(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Query security group
func (c *ClientGRPC) QuerySecurityGroup(ctx context.Context, hostIp, accessToken, tenantId,
	securityGroupId string) (response string, error error) {
	req := &resservice.QuerySecurityGroupRequest{
		AccessToken:          accessToken,
		HostIp:               hostIp,
		TenantId:             tenantId,
		SecurityGroupId:      securityGroupId,
	}
	resp, err := c.securityGroupClient.QuerySecurityGroup(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Delete security group
func (c *ClientGRPC) DeleteSecurityGroup(ctx context.Context, hostIp, accessToken, tenantId,
	securityGroupId string) (response string, error error) {
	req := &resservice.DeleteSecurityGroupRequest{
		AccessToken:          accessToken,
		HostIp:               hostIp,
		TenantId:             tenantId,
		SecurityGroupId:      securityGroupId,
	}
	resp, err := c.securityGroupClient.DeleteSecurityGroup(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Create security group rules
func (c *ClientGRPC) CreateSecurityGroupRules(ctx context.Context, securityGroupRules models.SecurityGroupRules,
	hostIp, accessToken, tenantId string) (response string, error error) {

	secGroupRule := &resservice.CreateSecurityGroupRuleRequest_SecurityGroupRule{
		SecurityGroupId: securityGroupRules.Securitygroupid,
		Direction:       securityGroupRules.Direction,
		Protocol:        securityGroupRules.Protocol,
		Ethertype:       securityGroupRules.Ethertype,
		PortRangeMax:    securityGroupRules.PortRangeMax,
		PortRangeMin:    securityGroupRules.PortRangeMin,
		RemoteIpPrefix:  securityGroupRules.Remoteipprefix,
		RemoteGroupId:   securityGroupRules.RemoteGroupID,
	}
	req := &resservice.CreateSecurityGroupRuleRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		SecurityGroupRule: secGroupRule,
	}
	resp, err := c.securityGroupClient.CreateSecurityGroupRule(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Query security group rules
func (c *ClientGRPC) QuerySecurityGroupRules(ctx context.Context, hostIp, accessToken, tenantId,
	securityGroupId string) (response string, error error) {
	req := &resservice.QuerySecurityGroupRuleRequest{
		AccessToken:          accessToken,
		HostIp:               hostIp,
		TenantId:             tenantId,
		SecurityGroupId:      securityGroupId,
	}
	resp, err := c.securityGroupClient.QuerySecurityGroupRule(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Delete security group rule
func (c *ClientGRPC) DeleteSecurityGroupRule(ctx context.Context, hostIp, accessToken, tenantId,
	securityGroupRuleId string) (response string, error error) {
	req := &resservice.DeleteSecurityGroupRuleRequest{
		AccessToken:          accessToken,
		HostIp:               hostIp,
		TenantId:             tenantId,
		SecurityGroupRuleId:  securityGroupRuleId,
	}
	resp, err := c.securityGroupClient.DeleteSecurityGroupRule(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Query images
func (c *ClientGRPC) QueryImages(ctx context.Context, hostIp, accessToken,
	tenantId, imageId string) (response string, error error) {
	req := &resservice.QueryVmImageRequest{
		AccessToken:          accessToken,
		HostIp:               hostIp,
		TenantId:             tenantId,
		ImageId:              imageId,
	}
	resp, err := c.vmImageClient.QueryVmImage(ctx, req)
	if err != nil {
		log.Error("Error ", err.Error())
		return "", err
	}
	return resp.Response, err
}

// Delete image
func (c *ClientGRPC) DeleteImage(ctx context.Context, hostIp, accessToken, tenantId,
	imageId string) (response string, error error) {
	req := &resservice.DeleteVmImageRequest{
		AccessToken:          accessToken,
		HostIp:               hostIp,
		TenantId:             tenantId,
		ImageId:              imageId,
	}
	resp, err := c.vmImageClient.DeleteVmImage(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Create Image
func (c *ClientGRPC) CreateImage(ctx context.Context, image models.Image, hostIp, accessToken,
	tenantId string) (response string, error error) {
	reqImage := &resservice.CreateVmImageRequest_Image{
		Name:            image.Name,
		ContainerFormat: image.Containerformat,
		DiskFormat:      image.Diskformat,
		MinRam:          image.Minram,
		MinDisk:         image.Mindisk,
		Properties:      image.Properties,
	}

	req := &resservice.CreateVmImageRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		Image:        reqImage,
	}
	resp, err := c.vmImageClient.CreateVmImage(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Import Image
func (c *ClientGRPC) ImportImage(ctx context.Context, importImage models.ImportImage, hostIp, accessToken,
	tenantId string) (response string, error error) {
	req := &resservice.ImportVmImageRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		ImageId:       importImage.Imageid,
		ResourceUri:   importImage.Resourceuri,
	}
	resp, err := c.vmImageClient.ImportVmImage(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Create Server
func (c *ClientGRPC) CreateServer(ctx context.Context, server models.Server, hostIp, accessToken,
	tenantId string) (response string, error error) {

	reqServer := &resservice.CreateVmRequest_Server{
		Name:             server.Name,
		Flavor:           server.Flavor,
		Image:            server.Image,
		AvailabilityZone: server.Availabilityzone,
		UserData:         server.UserData,
		ConfigDrive:      server.Configdrive,
		SecurityGroups:   server.Securitygroups,
		Networks:         server.Networks,
	}

	req := &resservice.CreateVmRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		Server:        reqServer,
	}
	resp, err := c.vmClient.CreateVm(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Query Server
func (c *ClientGRPC) QueryServer(ctx context.Context, hostIp, accessToken,
	tenantId, serverId string) (response string, error error) {
	req := &resservice.QueryVmRequest{
		AccessToken:          accessToken,
		HostIp:               hostIp,
		TenantId:             tenantId,
		VmId:                 serverId,
	}
	resp, err := c.vmClient.QueryVm(ctx, req)
	if err != nil {
		log.Error("Error ", err.Error())
		return "", err
	}
	return resp.Response, err
}

// Operate Server
func (c *ClientGRPC) OperateServer(ctx context.Context, operateServer models.OperateServer, hostIp, accessToken,
	tenantId, serverId string) (response string, error error) {
	rebootReq := &resservice.OperateVmRequest_Reboot{
		Type: operateServer.Reboot,
	}

	createImageReq := &resservice.OperateVmRequest_CreateImage{
		Name: operateServer.Createimage.Name,
		Metadata: operateServer.Createimage.Metadata,
	}
	req := &resservice.OperateVmRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		VmId:          serverId,
		Action:        operateServer.Action,
		Reboot:        rebootReq,
		CreateImage:   createImageReq,
	}
	resp, err := c.vmClient.OperateVm(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Delete server
func (c *ClientGRPC) DeleteServer(ctx context.Context, hostIp, accessToken, tenantId,
	serverId string) (response string, error error) {
	req := &resservice.DeleteVmRequest{
		AccessToken:          accessToken,
		HostIp:               hostIp,
		TenantId:             tenantId,
		VmId:                 serverId,
	}
	resp, err := c.vmClient.DeleteVm(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Create network
func (c *ClientGRPC) CreateNetwork(ctx context.Context, network models.Network, hostIp, accessToken, tenantId string) (response string, error error) {
	reqNetwork := &resservice.CreateNetworkRequest_Network{
		Name:                    network.Name,
		AdminStateUp:            network.Adminstateup,
		Mtu:                     network.Mtu,
		ProviderNetworkType:     network.Providernetworktype,
		ProviderPhysicalNetwork: network.Providerphysicalnetwork,
		ProviderSegmentationId:  network.Providersegmentationid,
		QosPolicyId:             network.Qospolicyid,
		RouterExternal:          network.Routerexternal,
		Segments:                network.Segments,
		Shared:                  network.Shared,
		IsDefault:               network.Isdefault,
		Subnets:                 network.Subnets,
	}
	req := &resservice.CreateNetworkRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		Network:       reqNetwork,
	}
	resp, err := c.networkClient.CreateNetwork(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Query network
func (c *ClientGRPC) QueryNetwork(ctx context.Context, hostIp, accessToken, tenantId, networkId string) (response string, error error) {
	req := &resservice.QueryNetworkRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		NetworkId:     networkId,
	}
	resp, err := c.networkClient.QueryNetwork(ctx, req)
	if err != nil {
		log.Error("Error ", err.Error())
		return "", err
	}
	return resp.Response, err
}

// Delete network
func (c *ClientGRPC) DeleteNetwork(ctx context.Context, hostIp, accessToken, tenantId, networkId string) (response string, error error) {
	req := &resservice.DeleteNetworkRequest{
		AccessToken:   accessToken,
		HostIp:        hostIp,
		TenantId:      tenantId,
		NetworkId:      networkId,
	}
	resp, err := c.networkClient.DeleteNetwork(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}