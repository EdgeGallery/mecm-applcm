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
package server

import (
	"bytes"
	"context"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
	"io"
	"k8splugin/internal/lcmservice"
	"k8splugin/models"
	"k8splugin/pgdb"
	"k8splugin/pkg/adapter"
	"k8splugin/util"
	"net"
	"os"
	"strconv"
)

var (
	kubeconfigPath  = "/usr/app/config/"
)

// GRPC server
type ServerGRPC struct {
	server      *grpc.Server
	port        int
	certificate string
	key         string
	db          pgdb.Database
}

// GRPC service configuration used to create GRPC server
type ServerGRPCConfig struct {
	Certificate string
	Key         string
	Port        int
}

// Constructor to GRPC server
func NewServerGRPC(cfg ServerGRPCConfig) (s ServerGRPC) {
	s.port = cfg.Port
	s.certificate = cfg.Certificate
	s.key = cfg.Key
	log.Infof("Binding is successful")
	return
}

// Start GRPC server and start listening on the port
func (s *ServerGRPC) Listen() (err error) {
	var (
		listener  net.Listener
		grpcOpts  []grpc.ServerOption
		grpcCreds credentials.TransportCredentials
	)

	// Listen announces on the network address
	listener, err = net.Listen("tcp", ":"+strconv.Itoa(s.port))
	if err != nil {
		log.Fatalf("failed to listen on specified port")
	}
	log.Info("Server started listening on specified port")

	// Secure connection if asked
	if s.certificate != "" && s.key != "" {
		grpcCreds, err = credentials.NewServerTLSFromFile(
			s.certificate, s.key)
		if err != nil {
			log.Fatalf("failed to create tls grpc server using given cert and key")
		}
		grpcOpts = append(grpcOpts, grpc.Creds(grpcCreds))
	}

	// Register server with GRPC
	s.server = grpc.NewServer(grpcOpts...)
	lcmservice.RegisterAppLCMServer(s.server, s)

	log.Info("Server registered with GRPC")

	// Server start serving
	err = s.server.Serve(listener)
	if err != nil {
		log.Fatalf("failed to listen for grpc connections.")
		return err
	}
	return
}

// Query HELM chart
func (s *ServerGRPC) Query(_ context.Context, req *lcmservice.QueryRequest) (resp *lcmservice.QueryResponse, err error) {

	// Input validation
	if req.GetHostIp() == "" {
		return nil, s.logError(status.Errorf(codes.InvalidArgument, "HostIP can't be null", err))
	}

	// Create HELM Client
	hc, err := adapter.NewHelmClient(req.GetHostIp())
	if os.IsNotExist(err) {
		return nil, s.logError(status.Errorf(codes.InvalidArgument,
			"Kubeconfig corresponding to given Edge can't be found. Err: %s", err))
	}

	// Query Chart
	r, err := hc.QueryChart("1")
	if err != nil {
		return nil, s.logError(status.Errorf(codes.NotFound, "Chart not found for workloadId: %s. Err: %s",
			"1", err))
	}
	resp = &lcmservice.QueryResponse{
		Response: r,
	}
	return resp, nil
}

// Terminate HELM charts
func (s *ServerGRPC) Terminate(ctx context.Context, req *lcmservice.TerminateRequest) (resp *lcmservice.TerminateResponse, err error) {
	log.Info("In Terminate")

	hostIp, appInsId, resp, err := s.validateInputParamsForTerm(req)
	if err != nil {
		return
	}
	appInstanceRecord := &models.AppInstanceInfo{
		AppInsId: appInsId,
	}
	s.initDbAdapter()
	readErr := s.db.ReadData(appInstanceRecord, "app_ins_id")
	if readErr != nil {
		return nil, s.logError(status.Errorf(codes.InvalidArgument,
			"App info record does not exist in database. Err: %s", readErr))
	}

	// Create HELM client
	hc, err := adapter.NewHelmClient(hostIp)
	if os.IsNotExist(err) {
		return nil, s.logError(status.Errorf(codes.InvalidArgument,
			"Kubeconfig corresponding to given Edge can't be found. Err: %s", err))
	}

	// Uninstall chart
	err = hc.UninstallChart(appInstanceRecord.WorkloadId)

	if err != nil {
		resp = &lcmservice.TerminateResponse{
			Status: "Failure",
		}

		return resp, s.logError(status.Errorf(codes.NotFound, "Chart not found for workloadId: %s. Err: %s",
			appInstanceRecord.WorkloadId, err))
	} else {
		resp = &lcmservice.TerminateResponse{
			Status: "Success",
		}
		return resp, nil
	}
}

// Instantiate HELM Chart
func (s *ServerGRPC) Instantiate(stream lcmservice.AppLCM_InstantiateServer) (err error) {
	log.Info("Recieved instantiate request")

	hostIp, appInsId, err := s.validateInputParamsForInstan(stream)
	if err != nil {
		return
	}

	helmPkg, err := s.getHelmPackage(stream)
	if err != nil {
		return err
	}

	// Create HELM client
	hc, err := adapter.NewHelmClient(hostIp)
	if os.IsNotExist(err) {
		return s.logError(status.Errorf(codes.InvalidArgument,
			"Kubeconfig corresponding to edge can't be found. Err: %s", err))
	}

	releaseName, err := hc.InstallChart(helmPkg)
	var res lcmservice.InstantiateResponse
	if err != nil {
		res.Status = "Failure"
		log.Info("Instantiation Failed")
	} else {
		res.Status = "Success"
		log.Info("Successful Instantiation")
		err := s.insertOrUpdateAppInsRecord(appInsId, hostIp, releaseName)
		if err != nil {
			return err
		}
	}

	err = stream.SendAndClose(&res)
	if err != nil {
		return s.logError(status.Errorf(codes.Unknown, "cannot send response: %v", err))
	}
	return
}

// Query KPI
func (s *ServerGRPC) QueryKPI(_ context.Context,
	request *lcmservice.QueryKPIRequest) (*lcmservice.QueryKPIResponse, error) {
	panic("implement me")
}

// Query Mep capabilities
func (s *ServerGRPC) QueryMepCapabilities(ctx context.Context,
	request *lcmservice.QueryMepCapRequest) (*lcmservice.QueryMepCapResponse, error) {
	panic("implement me")
}

// Context Error
func (s *ServerGRPC) contextError(ctx context.Context) error {
	switch ctx.Err() {
	case context.Canceled:
		return s.logError(status.Error(codes.Canceled, "request is canceled"))
	case context.DeadlineExceeded:
		return s.logError(status.Error(codes.DeadlineExceeded, "deadline is exceeded"))
	default:
		return nil
	}
}

// Logging error
func (s *ServerGRPC) logError(err error) error {
	if err != nil {
		log.Errorf("Error Information: ", err)
	}
	return err
}

// Validate input parameters for instantiation
func (s *ServerGRPC) validateInputParamsForInstan(stream lcmservice.AppLCM_InstantiateServer) (string, string, error) {
	// Receive metadata which is access token
	req, err := stream.Recv()
	if err != nil {
		return "", "", s.logError(status.Errorf(codes.InvalidArgument, util.CannotReceivePackage, err))
	}
	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken)
	if err != nil {
		return "", "", s.logError(status.Errorf(codes.InvalidArgument, "AccessToken is invalid", err))
	}

	// Receive metadata which is app instance id
	req, err = stream.Recv()
	if err != nil {
		return "", "", s.logError(status.Errorf(codes.InvalidArgument, util.CannotReceivePackage, err))
	}
	appInsId := req.GetAppInstanceId()
	err = util.ValidateUUID(appInsId)
	if err != nil {
		return "", "", s.logError(status.Errorf(codes.InvalidArgument, "App instance id is invalid", err))
	}

	// Receive metadata which is host ip
	req, err = stream.Recv()
	if err != nil {
		return "", "", s.logError(status.Errorf(codes.InvalidArgument, util.CannotReceivePackage, err))
	}
	hostIp := req.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", "", s.logError(status.Errorf(codes.InvalidArgument, "HostIp is invalid", err))
	}

	return hostIp, appInsId, nil
}

// Validate input parameters for termination
func (s *ServerGRPC) validateInputParamsForTerm(
	req *lcmservice.TerminateRequest) (hostIp string, appInsId string, resp *lcmservice.TerminateResponse, err error) {
	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken)
	if err != nil {
		return "", "", nil, s.logError(status.Errorf(codes.InvalidArgument,
			"AccessToken is invalid", err))
	}

	hostIp = req.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", "", nil, s.logError(status.Errorf(codes.InvalidArgument,
			"HostIp is invalid", err))
	}

	appInsId = req.GetAppInstanceId()
	err = util.ValidateUUID(appInsId)
	if err != nil {
		return "", "", nil, s.logError(status.Errorf(codes.InvalidArgument,
			"AppInsId is invalid", err))
	}

	return hostIp, appInsId, nil, nil
}
// Get helm package
func (s *ServerGRPC) getHelmPackage(stream lcmservice.AppLCM_InstantiateServer) (buf bytes.Buffer, err error) {
	// Receive package
	helmPkg := bytes.Buffer{}
	for {
		err := s.contextError(stream.Context())
		if err != nil {
			return helmPkg, err
		}

		log.Debug("Waiting to receive more data")

		req, err := stream.Recv()
		if err == io.EOF {
			log.Debug("No more data")
			break
		}
		if err != nil {
			return helmPkg, s.logError(status.Errorf(codes.Unknown, "cannot receive chunk data: %v", err))
		}

		// Receive chunk and write to helm package
		chunk := req.GetPackage()

		_, err = helmPkg.Write(chunk)
		if err != nil {
			return helmPkg, s.logError(status.Errorf(codes.Internal, "cannot write chunk data: %v", err))
		}
	}
	return helmPkg, nil
}


// Init Db adapter
func (c *ServerGRPC) initDbAdapter() {
	//	dbAdapter := os.Getenv("dbAdapter")
	dbAdapter := "pgDb"
	switch dbAdapter {
	case "pgDb":
		if c.db == nil {
			pgDbadapter, err := pgdb.NewPgDbAdapter()
			if err != nil {
				return
			}
			c.db = pgDbadapter
		}
		return
	default:
		return
	}
}