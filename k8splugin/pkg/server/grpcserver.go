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
	"k8splugin/conf"
	"k8splugin/internal/lcmservice"
	"k8splugin/models"
	"k8splugin/pgdb"
	"k8splugin/pkg/adapter"
	"k8splugin/util"
	"net"
	"os"
)

var (
	kubeconfigPath = "/usr/app/config/"
)

// GRPC server
type ServerGRPC struct {
	server       *grpc.Server
	port         string
	address      string
	certificate  string
	key          string
	db           pgdb.Database
	serverConfig *conf.ServerConfigurations
}

// GRPC service configuration used to create GRPC server
type ServerGRPCConfig struct {
	Port         string
	Address      string
	ServerConfig *conf.ServerConfigurations
}

// Constructor to GRPC server
func NewServerGRPC(cfg ServerGRPCConfig) (s ServerGRPC) {
	s.port = cfg.Port
	s.address = cfg.Address
	s.certificate = cfg.ServerConfig.Certfilepath
	s.key = cfg.ServerConfig.Keyfilepath
	s.serverConfig = cfg.ServerConfig
	dbAdapter, err := pgdb.GetDbAdapter()
	if err != nil {
		log.Error("Failed to get database")
		os.Exit(1)
	}
	s.db = dbAdapter
	log.Infof("Binding is successful")
	return
}

// Start GRPC server and start listening on the port
func (s *ServerGRPC) Listen() (err error) {
	var (
		listener net.Listener
	)

	// Listen announces on the network address
	listener, err = net.Listen("tcp", s.address+":"+s.port)
	if err != nil {
		log.Error("failed to listen on specified port")
		return err
	}
	log.Info("Server started listening on configured port")

	if !s.serverConfig.Sslnotenabled {
		tlsConfig, err := util.GetTLSConfig(s.serverConfig, s.certificate, s.key)
		if err != nil {
			log.Error("failed to load certificates")
			return err
		}

		// Create the TLS credentials
		creds := credentials.NewTLS(tlsConfig)

		// Create server with TLS credentials
		s.server = grpc.NewServer(grpc.Creds(creds))
	} else {
		// Create server without TLS credentials
		s.server = grpc.NewServer()
	}

	lcmservice.RegisterAppLCMServer(s.server, s)
	log.Infof("Server registered with GRPC")

	// Server start serving
	err = s.server.Serve(listener)
	if err != nil {
		log.Error("failed to listen for GRPC connections.")
		return err
	}
	return
}

// Query HELM chart
func (s *ServerGRPC) Query(_ context.Context, req *lcmservice.QueryRequest) (resp *lcmservice.QueryResponse, err error) {

	// Input validation
	hostIp, appInsId, err := s.validateInputParamsForQuery(req)
	if err != nil {
		return
	}

	// Create HELM Client
	hc, err := adapter.NewHelmClient(hostIp)
	if os.IsNotExist(err) {
		return nil, s.logError(status.Error(codes.InvalidArgument,
			"Kubeconfig corresponding to given Edge can't be found."))
	}

	appInstanceRecord := &models.AppInstanceInfo{
		AppInsId: appInsId,
	}
	readErr := s.db.ReadData(appInstanceRecord, util.AppInsId)
	if readErr != nil {
		return nil, s.logError(status.Error(codes.InvalidArgument,
			"App info record does not exist in database."))
	}

	// Query Chart
	r, err := hc.QueryChart(appInstanceRecord.WorkloadId)
	if err != nil {
		return nil, s.logError(status.Errorf(codes.NotFound, "Chart not found for workloadId: %s. Err: %s",
			appInstanceRecord.WorkloadId, err))
	}
	resp = &lcmservice.QueryResponse{
		Response: r,
	}
	log.Info("Query is success")
	return resp, nil
}

// Terminate HELM charts
func (s *ServerGRPC) Terminate(ctx context.Context, req *lcmservice.TerminateRequest) (resp *lcmservice.TerminateResponse, err error) {
	log.Info("In Terminate")

	hostIp, appInsId, err := s.validateInputParamsForTerm(req)
	if err != nil {
		return
	}
	appInstanceRecord := &models.AppInstanceInfo{
		AppInsId: appInsId,
	}
	readErr := s.db.ReadData(appInstanceRecord, util.AppInsId)
	if readErr != nil {
		return nil, s.logError(status.Error(codes.InvalidArgument,
			"App info record does not exist in database."))
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
			Status: util.Failure,
		}

		return resp, s.logError(status.Errorf(codes.NotFound, "Chart not found for workloadId: %s. Err: %s",
			appInstanceRecord.WorkloadId, err))
	} else {
		resp = &lcmservice.TerminateResponse{
			Status: util.Success,
		}
		return resp, nil
	}
}

// Instantiate HELM Chart
func (s *ServerGRPC) Instantiate(stream lcmservice.AppLCM_InstantiateServer) error {
	log.Info("Recieved instantiate request")

	hostIp, appInsId, err := s.validateInputParamsForInstan(stream)
	if err != nil {
		return err
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
		res.Status = util.Failure
		log.Info("Instantiation Failed")
	} else {
		res.Status = util.Success
		log.Info("Successful Instantiation")
		err = s.insertOrUpdateAppInsRecord(appInsId, hostIp, releaseName)
		if err != nil {
			return err
		}
	}

	err = stream.SendAndClose(&res)
	if err != nil {
		return s.logError(status.Errorf(codes.Unknown, "cannot send response: %v", err))
	}
	return nil
}

// Upload file configuration
func (s *ServerGRPC) UploadConfig(stream lcmservice.AppLCM_UploadConfigServer) (err error) {

	hostIp, err := s.validateInputParamsForUploadCfg(stream)
	if err != nil {
		return
	}

	file, err := s.getUploadConfigFile(stream)
	if err != nil {
		return err
	}

	if !util.CreateDir(kubeconfigPath) {
		log.Infof("failed to create config dir")
		return err
	}

	configPath := kubeconfigPath + hostIp
	newFile, err := os.Create(configPath)
	if err != nil {
		log.Info("config file upload error.")
		return err
	}

	defer newFile.Close()
	_, err = newFile.Write(file.Bytes())

	var res lcmservice.UploadCfgResponse

	if err != nil {
		res.Status = util.Failure
		log.Error("config IO operation error.")
	} else {
		res.Status = util.Success
		log.Info("Uploaded config file successfully")
	}

	err = stream.SendAndClose(&res)
	if err != nil {
		return s.logError(status.Errorf(codes.Unknown, "cannot send response: %v", err))
	}

	return
}

// Remove file configuration
func (s *ServerGRPC) RemoveConfig(_ context.Context,
	request *lcmservice.RemoveCfgRequest) (*lcmservice.RemoveCfgResponse, error) {
	resp := &lcmservice.RemoveCfgResponse{
		Status: util.Failure,
	}

	hostIp, err := validateInputParamsForRemoveCfg(request)
	if err != nil {
		return resp, err
	}
	configPath := kubeconfigPath + hostIp
	err = os.Remove(configPath)
	if err != nil {
		log.Error("host config delete failed.")
		return resp, err
	}

	resp = &lcmservice.RemoveCfgResponse{
		Status: util.Success,
	}
	log.Info("host configuration file deleted successfully.")
	return resp, nil
}

// Validate input parameters for remove config
func validateInputParamsForRemoveCfg(request *lcmservice.RemoveCfgRequest) (string, error) {
	accessToken := request.GetAccessToken()
	err := util.ValidateAccessToken(accessToken)
	if err != nil {
		log.Info("accessToken validation failed, invalid accessToken")
		return "", err
	}

	hostIp := request.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		log.Info("hostIp validation failed, invalid ipaddress")
		return "", err
	}
	return hostIp, nil
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
		log.Errorf("Error Information: %v", err)
	}
	return err
}

// Validate input parameters for instantiation
func (s *ServerGRPC) validateInputParamsForInstan(stream lcmservice.AppLCM_InstantiateServer) (string, string, error) {
	// Receive metadata which is access token
	req, err := stream.Recv()
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}
	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument, util.AccssTokenIsInvalid))
	}

	// Receive metadata which is app instance id
	req, err = stream.Recv()
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}
	appInsId := req.GetAppInstanceId()
	err = util.ValidateUUID(appInsId)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument, "App instance id is invalid"))
	}

	// Receive metadata which is host ip
	req, err = stream.Recv()
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}
	hostIp := req.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument, util.HostIpIsInvalid))
	}

	return hostIp, appInsId, nil
}

// Validate input parameters for termination
func (s *ServerGRPC) validateInputParamsForTerm(
	req *lcmservice.TerminateRequest) (hostIp string, appInsId string, err error) {
	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument,
			util.AccssTokenIsInvalid))
	}

	hostIp = req.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument,
			util.HostIpIsInvalid))
	}

	appInsId = req.GetAppInstanceId()
	err = util.ValidateUUID(appInsId)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument,
			"AppInsId is invalid"))
	}

	return hostIp, appInsId, nil
}

// Validate input parameters for upload configuration
func (s *ServerGRPC) validateInputParamsForUploadCfg(
	stream lcmservice.AppLCM_UploadConfigServer) (hostIp string, err error) {
	// Receive metadata which is accesstoken
	req, err := stream.Recv()
	if err != nil {
		log.Error(util.CannotReceivePackage)
		return
	}
	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken)
	if err != nil {
		return "", s.logError(status.Error(codes.InvalidArgument, util.AccssTokenIsInvalid))
	}

	// Receive metadata which is host ip
	req, err = stream.Recv()
	if err != nil {
		log.Error(util.CannotReceivePackage)
		return
	}
	hostIp = req.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", s.logError(status.Error(codes.InvalidArgument, util.HostIpIsInvalid))
	}

	return hostIp, nil
}

// Validate input parameters for Query
func (s *ServerGRPC) validateInputParamsForQuery(
	req *lcmservice.QueryRequest) (hostIp string, appInsId string, err error) {

	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument,
			util.AccssTokenIsInvalid))
	}

	hostIp = req.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument, util.HostIpIsInvalid))
	}

	appInsId = req.GetAppInstanceId()
	err = util.ValidateUUID(appInsId)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument,"AppInsId is invalid"))
	}

	return hostIp, appInsId,nil
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

// Get upload configuration file
func (s *ServerGRPC) getUploadConfigFile(stream lcmservice.AppLCM_UploadConfigServer) (but bytes.Buffer, err error){
	// Receive upload config file
	file := bytes.Buffer{}
	for {
		err := s.contextError(stream.Context())
		if err != nil {
			return file, err
		}

		log.Debug("Waiting to receive more data")

		req, err := stream.Recv()
		if err == io.EOF {
			log.Debug("No more data")
			break
		}
		if err != nil {
			return file, s.logError(status.Errorf(codes.Unknown, "cannot receive chunk data: %v", err))
		}

		// Receive chunk and write to helm package
		chunk := req.GetConfigFile()

		_, err = file.Write(chunk)
		if err != nil {
			return file, s.logError(status.Errorf(codes.Internal, "cannot write chunk data: %v", err))
		}
	}
	return file, nil
}

// Insert or update application instance record
func (s *ServerGRPC) insertOrUpdateAppInsRecord(appInsId, hostIp, releaseName string) (err error) {
	appInfoRecord := &models.AppInstanceInfo{
		AppInsId:   appInsId,
		HostIp:     hostIp,
		WorkloadId: releaseName,
	}
	err = s.db.InsertOrUpdateData(appInfoRecord, util.AppInsId)
	if err != nil && err.Error() != "LastInsertId is not supported by this driver" {
		return s.logError(status.Error(codes.InvalidArgument,
			"Failed to save app info record to database."))
	}
	return nil
}
