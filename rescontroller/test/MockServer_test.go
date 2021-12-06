package test

import (
	"context"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	resservice "rescontroller/internal/internal_resourcemanager"
)

// GRPC server
type ServerGRPC struct {
	server  *grpc.Server
	Address string
}

// Flavor manager server
type FlavorManagerServer struct {
	server  *grpc.Server
	Address string
}

// Network manager server
type NetworkManagerServer struct {
	server  *grpc.Server
	Address string
}

// Security group manager server
type SecurityGroupManagerServer struct {
	server  *grpc.Server
	Address string
}

// Vm server
type VmManagerServer struct {
	server  *grpc.Server
	Address string
}

// Vm Image server
type VmImageMangerServer struct {
	server  *grpc.Server
	Address string
}

func (c VmImageMangerServer) UploadVmImage(server resservice.VmImageManger_UploadVmImageServer) error {
	panic("implement me")
}

func (c VmImageMangerServer) DownloadVmImage(request *resservice.DownloadVmImageRequest, server resservice.VmImageManger_DownloadVmImageServer) error {
	panic("implement me")
}

const SUCCESS_RETURN = "Success"

func (c FlavorManagerServer) CreateFlavor(ctx context.Context, request *resservice.CreateFlavorRequest) (*resservice.CreateFlavorResponse, error) {
	resp := &resservice.CreateFlavorResponse{
		Status: SUCCESS_RETURN,
	}
    return  resp, nil
}

func (c FlavorManagerServer) DeleteFlavor(ctx context.Context, request *resservice.DeleteFlavorRequest) (*resservice.DeleteFlavorResponse, error) {
	resp := &resservice.DeleteFlavorResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}

func (c FlavorManagerServer) QueryFlavor(ctx context.Context, request *resservice.QueryFlavorRequest) (*resservice.QueryFlavorResponse, error) {
	resp := &resservice.QueryFlavorResponse{
		Response: SUCCESS_RETURN,
	}
	return  resp, nil
}


func (c NetworkManagerServer) CreateNetwork(ctx context.Context, request *resservice.CreateNetworkRequest) (*resservice.CreateNetworkResponse, error) {
	resp := &resservice.CreateNetworkResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}

func (c NetworkManagerServer) DeleteNetwork(ctx context.Context, request *resservice.DeleteNetworkRequest) (*resservice.DeleteNetworkResponse, error) {
	resp := &resservice.DeleteNetworkResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}

func (c NetworkManagerServer) QueryNetwork(ctx context.Context, request *resservice.QueryNetworkRequest) (*resservice.QueryNetworkResponse, error) {
	resp := &resservice.QueryNetworkResponse{
		Response: SUCCESS_RETURN,
	}
	return  resp, nil
}

func (c SecurityGroupManagerServer) CreateSecurityGroup(context.Context, *resservice.CreateSecurityGroupRequest) (*resservice.CreateSecurityGroupResponse, error) {
	resp := &resservice.CreateSecurityGroupResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}
func (c SecurityGroupManagerServer) DeleteSecurityGroup(context.Context, *resservice.DeleteSecurityGroupRequest) (*resservice.DeleteSecurityGroupResponse, error) {
	resp := &resservice.DeleteSecurityGroupResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}
func (c SecurityGroupManagerServer) QuerySecurityGroup(context.Context, *resservice.QuerySecurityGroupRequest) (*resservice.QuerySecurityGroupResponse, error) {
	resp := &resservice.QuerySecurityGroupResponse{
		Response: SUCCESS_RETURN,
	}
	return  resp, nil
}
func (c SecurityGroupManagerServer) CreateSecurityGroupRule(context.Context, *resservice.CreateSecurityGroupRuleRequest) (*resservice.CreateSecurityGroupRuleResponse, error) {
	resp := &resservice.CreateSecurityGroupRuleResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}
func (c SecurityGroupManagerServer) DeleteSecurityGroupRule(context.Context, *resservice.DeleteSecurityGroupRuleRequest) (*resservice.DeleteSecurityGroupRuleResponse, error) {
	resp := &resservice.DeleteSecurityGroupRuleResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}

func (c VmManagerServer) CreateVm(context.Context, *resservice.CreateVmRequest) (*resservice.CreateVmResponse, error) {
	resp := &resservice.CreateVmResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}
func (c VmManagerServer) QueryVm(context.Context, *resservice.QueryVmRequest) (*resservice.QueryVmResponse, error) {
	resp := &resservice.QueryVmResponse{
		Response: SUCCESS_RETURN,
	}
	return  resp, nil
}
func (c VmManagerServer) OperateVm(context.Context, *resservice.OperateVmRequest) (*resservice.OperateVmResponse, error) {
	resp := &resservice.OperateVmResponse{
		Response: SUCCESS_RETURN,
	}
	return  resp, nil
}
func (c VmManagerServer) DeleteVm(context.Context, *resservice.DeleteVmRequest) (*resservice.DeleteVmResponse, error) {
	resp := &resservice.DeleteVmResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}

func (c VmImageMangerServer) CreateVmImage(context.Context, *resservice.CreateVmImageRequest) (*resservice.CreateVmImageResponse, error) {
	resp := &resservice.CreateVmImageResponse{
		Response: SUCCESS_RETURN,
	}
	return  resp, nil
}
func (VmImageMangerServer) DeleteVmImage(context.Context, *resservice.DeleteVmImageRequest) (*resservice.DeleteVmImageResponse, error) {
	resp := &resservice.DeleteVmImageResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}
func (VmImageMangerServer) ImportVmImage(context.Context, *resservice.ImportVmImageRequest) (*resservice.ImportVmImageResponse, error) {
	resp := &resservice.ImportVmImageResponse{
		Status: SUCCESS_RETURN,
	}
	return  resp, nil
}
func (VmImageMangerServer) QueryVmImage(context.Context, *resservice.QueryVmImageRequest) (*resservice.QueryVmImageResponse, error) {
	resp := &resservice.QueryVmImageResponse{
		Response: SUCCESS_RETURN,
	}
	return  resp, nil
}

// Start GRPC server and start listening on the port
func (s *ServerGRPC) Listen() (err error) {
	var (
		listener net.Listener
	)
	// Listen announces on the network address
	listener, err = net.Listen("tcp", s.Address)
	if err != nil {
		log.Error("failed to listen on specified port")
		return err
	}
	log.Info("Mock Server started listening on configured port")

	// Create server without TLS credentials
	s.server = grpc.NewServer()
	var appFlavorManagerServer FlavorManagerServer
	var appNetworkManagerServer NetworkManagerServer
	var appSecurityGroupManageServer SecurityGroupManagerServer
	var appVmManageServer VmManagerServer
	var appVmImageMangeServer VmImageMangerServer

	resservice.RegisterFlavorManagerServer(s.server, appFlavorManagerServer)
	resservice.RegisterNetworkManagerServer(s.server, appNetworkManagerServer)
	resservice.RegisterSecurityGroupManagerServer(s.server, appSecurityGroupManageServer)
	resservice.RegisterVmManagerServer(s.server, appVmManageServer)
	resservice.RegisterVmImageMangerServer(s.server, appVmImageMangeServer)
	log.Infof("Mock server registered with GRPC")

	// Server start serving
	err = s.server.Serve(listener)
	if err != nil {
		log.Error("failed to listen for GRPC connections.")
		return err
	}
	log.Error("server exited")
	return
}