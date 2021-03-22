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
	"context"
	"errors"
	"io"
	"lcmcontroller/internal/lcmservice"
	"net"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
)

// GRPC server
type ServerGRPC struct {
	server  *grpc.Server
	Address string
}

// GRPC server
type AppLCMServer struct {
	server  *grpc.Server
	Address string
}

func (a AppLCMServer) Instantiate(ctx context.Context, request *lcmservice.InstantiateRequest) (*lcmservice.InstantiateResponse, error) {
	resp := &lcmservice.InstantiateResponse{
		Status: SUCCESS_RETURN,
	}
	return resp, nil
}

func (a AppLCMServer) Terminate(ctx context.Context, request *lcmservice.TerminateRequest) (*lcmservice.TerminateResponse, error) {
	resp := &lcmservice.TerminateResponse{
		Status: SUCCESS_RETURN,
	}
	return resp, nil
}

func (a AppLCMServer) Query(ctx context.Context, request *lcmservice.QueryRequest) (*lcmservice.QueryResponse, error) {
	resp := &lcmservice.QueryResponse{
		Response: "{\"Output\":\"Success\"}",
	}
	log.Info("Query is success")
	return resp, nil
}

func (a AppLCMServer) UploadConfig(stream lcmservice.AppLCM_UploadConfigServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			log.Debug(noMoreData)
			break
		}

		// Receive chunk and write to helm package
		_ = req.GetConfigFile()
	}

	var res lcmservice.UploadCfgResponse
	res.Status = SUCCESS_RETURN
	log.Info("Successful Upload")
	err := stream.SendAndClose(&res)
	if err != nil {
		log.Info("Failed to Upload")
		return errors.New("Failed Upload")
	}
	return nil
}

func (a AppLCMServer) RemoveConfig(ctx context.Context, request *lcmservice.RemoveCfgRequest) (*lcmservice.RemoveCfgResponse, error) {
	resp := &lcmservice.RemoveCfgResponse{
		Status: SUCCESS_RETURN,
	}
	log.Info("host configuration file deleted successfully.")
	return resp, nil
}

func (a AppLCMServer) WorkloadEvents(ctx context.Context, request *lcmservice.WorkloadEventsRequest) (*lcmservice.WorkloadEventsResponse, error) {
	resp := &lcmservice.WorkloadEventsResponse{
		Response: SUCCESS_RETURN,
	}
	return resp, nil
}

func (a AppLCMServer) UploadPackage(stream lcmservice.AppLCM_UploadPackageServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			log.Debug(noMoreData)
			break
		}

		// Receive chunk and write to helm package
		_ = req.GetPackage()
	}

	var res lcmservice.UploadPackageResponse
	res.Status = SUCCESS_RETURN
	log.Info("Successful Upload package")
	err := stream.SendAndClose(&res)
	if err != nil {
		log.Info("Failed to package Upload")
		return errors.New("Failed package Upload ")
	}
	return nil
}

func (a AppLCMServer) DeletePackage(ctx context.Context, request *lcmservice.DeletePackageRequest) (*lcmservice.DeletePackageResponse, error) {
	return nil, nil
}

/*func (s *ServerGRPC) UploadPackage(server lcmservice.AppLCM_UploadPackageServer) error {
	log.Info("not supported")
	return nil
}

func (s *ServerGRPC) DeletePackage(ctx context.Context, request *lcmservice.DeletePackageRequest) (*lcmservice.DeletePackageResponse, error) {
	log.Info("not supported")
	return nil, nil
}*/

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
	var appLCMServer AppLCMServer
	
	lcmservice.RegisterAppLCMServer(s.server, appLCMServer)
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

// Query HELM chart
func (s *ServerGRPC) Query(_ context.Context, req *lcmservice.QueryRequest) (resp *lcmservice.QueryResponse, err error) {
	resp = &lcmservice.QueryResponse{
		Response: "{\"Output\":\"Success\"}",
	}
	log.Info("Query is success")
	return resp, nil
}

// Terminate HELM charts
func (s *ServerGRPC) Terminate(ctx context.Context, req *lcmservice.TerminateRequest) (resp *lcmservice.TerminateResponse, err error) {
	resp = &lcmservice.TerminateResponse{
		Status: SUCCESS_RETURN,
	}
	return resp, nil
}

// Instantiate HELM Chart
func (s *ServerGRPC) Instantiate() (err error) {
	return nil
}

// Upload file configuration
func (s *ServerGRPC) UploadConfig(stream lcmservice.AppLCM_UploadConfigServer) (err error) {

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			log.Debug(noMoreData)
			break
		}

		// Receive chunk and write to helm package
		_ = req.GetConfigFile()
	}

	var res lcmservice.UploadCfgResponse
	res.Status = SUCCESS_RETURN
	log.Info("Successful Upload")
	err = stream.SendAndClose(&res)
	if err != nil {
		log.Info("Failed to Upload")
		return errors.New("Failed Upload")
	}
	return nil
}

// Remove file configuration
func (s *ServerGRPC) RemoveConfig(_ context.Context,
	request *lcmservice.RemoveCfgRequest) (*lcmservice.RemoveCfgResponse, error) {
	resp := &lcmservice.RemoveCfgResponse{
		Status: SUCCESS_RETURN,
	}
	log.Info("host configuration file deleted successfully.")
	return resp, nil
}

// Workload description
func (s *ServerGRPC) WorkloadEvents(ctx context.Context, request *lcmservice.WorkloadEventsRequest) (*lcmservice.WorkloadEventsResponse, error) {
	resp := &lcmservice.WorkloadEventsResponse{
		Response: SUCCESS_RETURN,
	}
	return resp, nil
}

