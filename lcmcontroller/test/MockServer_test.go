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
	"lcmcontroller/internal/internal_lcmservice"
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


// GRPC server
type VmImageServer struct {
	server  *grpc.Server
	Address string
}

func (a AppLCMServer) Instantiate(ctx context.Context, request *internal_lcmservice.InstantiateRequest) (*internal_lcmservice.InstantiateResponse, error) {
	resp := &internal_lcmservice.InstantiateResponse{
		Status: SUCCESS_RETURN,
	}
	return resp, nil
}

func (a AppLCMServer) Terminate(ctx context.Context, request *internal_lcmservice.TerminateRequest) (*internal_lcmservice.TerminateResponse, error) {
	resp := &internal_lcmservice.TerminateResponse{
		Status: SUCCESS_RETURN,
	}
	return resp, nil
}

func (a AppLCMServer) Query(ctx context.Context, request *internal_lcmservice.QueryRequest) (*internal_lcmservice.QueryResponse, error) {
	resp := &internal_lcmservice.QueryResponse{
		Response: "{\"Output\":\"Success\"}",
	}
	log.Info("Query is success")
	return resp, nil
}

func (a AppLCMServer) QueryKPI(ctx context.Context, request *internal_lcmservice.QueryKPIRequest) (*internal_lcmservice.QueryKPIResponse, error) {
	resp := &internal_lcmservice.QueryKPIResponse{
		Response: finalOutput,
	}
	log.Info("Query KPI is success")
	return resp, nil
}

func (a AppLCMServer) UploadConfig(stream internal_lcmservice.AppLCM_UploadConfigServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			log.Debug(noMoreData)
			break
		}

		// Receive chunk and write to helm package
		_ = req.GetConfigFile()
	}

	var res internal_lcmservice.UploadCfgResponse
	res.Status = SUCCESS_RETURN
	log.Info("Successful Upload")
	err := stream.SendAndClose(&res)
	if err != nil {
		log.Info("Failed to Upload")
		return errors.New("Failed Upload")
	}
	return nil
}

func (a AppLCMServer) RemoveConfig(ctx context.Context, request *internal_lcmservice.RemoveCfgRequest) (*internal_lcmservice.RemoveCfgResponse, error) {
	resp := &internal_lcmservice.RemoveCfgResponse{
		Status: SUCCESS_RETURN,
	}
	log.Info("host configuration file deleted successfully.")
	return resp, nil
}

func (a AppLCMServer) WorkloadEvents(ctx context.Context, request *internal_lcmservice.WorkloadEventsRequest) (*internal_lcmservice.WorkloadEventsResponse, error) {
	resp := &internal_lcmservice.WorkloadEventsResponse{
		Response: SUCCESS_RETURN,
	}
	return resp, nil
}

func (a AppLCMServer) QueryPackageStatus(ctx context.Context, request *internal_lcmservice.QueryPackageStatusRequest) (*internal_lcmservice.QueryPackageStatusResponse, error) {
	resp := &internal_lcmservice.QueryPackageStatusResponse{
		Response: SUCCESS_RETURN,
	}
	return resp, nil
}

func (a AppLCMServer) UploadPackage(stream internal_lcmservice.AppLCM_UploadPackageServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			log.Debug(noMoreData)
			break
		}

		// Receive chunk and write to helm package
		_ = req.GetPackage()
	}

	var res internal_lcmservice.UploadPackageResponse
	res.Status = SUCCESS_RETURN
	log.Info("Successful Upload package")
	err := stream.SendAndClose(&res)
	if err != nil {
		log.Info("Failed to package Upload")
		return errors.New("Failed package Upload ")
	}
	return nil
}

func (a AppLCMServer) DeletePackage(ctx context.Context, request *internal_lcmservice.DeletePackageRequest) (*internal_lcmservice.DeletePackageResponse, error) {
	resp := &internal_lcmservice.DeletePackageResponse{
		Status: SUCCESS_RETURN,
	}
	return resp, nil
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
	var appLCMServer AppLCMServer

	internal_lcmservice.RegisterAppLCMServer(s.server, appLCMServer)
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
func (s *ServerGRPC) Query(_ context.Context, req *internal_lcmservice.QueryRequest) (resp *internal_lcmservice.QueryResponse, err error) {
	resp = &internal_lcmservice.QueryResponse{
		Response: "{\"Output\":\"Success\"}",
	}
	log.Info("Query is success")
	return resp, nil
}

// Terminate HELM charts
func (s *ServerGRPC) Terminate(ctx context.Context, req *internal_lcmservice.TerminateRequest) (resp *internal_lcmservice.TerminateResponse, err error) {
	resp = &internal_lcmservice.TerminateResponse{
		Status: SUCCESS_RETURN,
	}
	return resp, nil
}

// Instantiate HELM Chart
func (s *ServerGRPC) Instantiate() (err error) {
	return nil
}

// Upload file configuration
func (s *ServerGRPC) UploadConfig(stream internal_lcmservice.AppLCM_UploadConfigServer) (err error) {

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			log.Debug(noMoreData)
			break
		}

		// Receive chunk and write to helm package
		_ = req.GetConfigFile()
	}

	var res internal_lcmservice.UploadCfgResponse
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
	request *internal_lcmservice.RemoveCfgRequest) (*internal_lcmservice.RemoveCfgResponse, error) {
	resp := &internal_lcmservice.RemoveCfgResponse{
		Status: SUCCESS_RETURN,
	}
	log.Info("host configuration file deleted successfully.")
	return resp, nil
}

// Workload description
func (s *ServerGRPC) WorkloadEvents(ctx context.Context, request *internal_lcmservice.WorkloadEventsRequest) (*internal_lcmservice.WorkloadEventsResponse, error) {
	resp := &internal_lcmservice.WorkloadEventsResponse{
		Response: SUCCESS_RETURN,
	}
	return resp, nil
}

