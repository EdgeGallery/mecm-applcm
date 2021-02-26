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
	"golang.org/x/time/rate"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/tap"
	"io"
	"k8splugin/conf"
	"k8splugin/internal/lcmservice"
	"k8splugin/models"
	"k8splugin/pgdb"
	"k8splugin/pkg/adapter"
	"k8splugin/util"
	"net"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
)

var (
	KubeconfigPath = "/usr/app/config/"
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

// Rate Limit
type RateLimit struct {
	lim *rate.Limiter
}

// New Rate Limit constructor
func NewRateLimit() *RateLimit {
	return &RateLimit{rate.NewLimiter(1, 200)}
}

// Constructor to GRPC server
func NewServerGRPC(cfg ServerGRPCConfig) (s ServerGRPC) {
	s.port = cfg.Port
	s.address = cfg.Address
	s.certificate = cfg.ServerConfig.Certfilepath
	s.key = cfg.ServerConfig.Keyfilepath
	s.serverConfig = cfg.ServerConfig
	dbAdapter, err := pgdb.GetDbAdapter(cfg.ServerConfig)
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
		s.server = grpc.NewServer(grpc.Creds(creds), grpc.InTapHandle(NewRateLimit().Handler))
	} else {
		// Create server without TLS credentials
		s.server = grpc.NewServer(grpc.InTapHandle(NewRateLimit().Handler))
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

// Handler to check service is over rate limit or not
func (t *RateLimit) Handler(ctx context.Context, info *tap.Info) (context.Context, error) {
	if !t.lim.Allow() {
		return nil, status.Errorf(codes.ResourceExhausted, "service is over rate limit")
	}
	return ctx, nil
}

// Pod Description
func (s *ServerGRPC) PodDescribe(ctx context.Context, req *lcmservice.PodDescribeRequest) (resp *lcmservice.PodDescribeResponse, err error) {

	resp = &lcmservice.PodDescribeResponse{
		Response: util.Failure,
	}

	err = s.displayReceivedMsg(ctx, util.PodDescribe)
	if err != nil {
		s.displayResponseMsg(ctx, util.PodDescribe, util.FailedToDispRecvMsg)
		return resp, err
	}

	// Input validation
	hostIp, appInsId, err := s.validateInputParamsForPodDesc(req)
	if err != nil {
		s.displayResponseMsg(ctx, util.PodDescribe, util.FailedToValInputParams)
		return resp, err
	}

	// Get Client
	client, err := adapter.GetClient(util.DeployType, hostIp)
	if err != nil {
		s.displayResponseMsg(ctx, util.PodDescribe, util.FailedToGetClient)
		return resp, err
	}

	appInstanceRecord := &models.AppInstanceInfo{
		AppInsId: appInsId,
	}
	readErr := s.db.ReadData(appInstanceRecord, util.AppInsId)
	if readErr != nil {
		log.Error(util.AppRecordDoesNotExit)
		s.displayResponseMsg(ctx, util.Query, util.AppRecordDoesNotExit)
		return resp, err
	}

	// Query Chart
	r, err := client.PodDescribe(appInstanceRecord.WorkloadId)
	if err != nil {
		s.displayResponseMsg(ctx, util.PodDescribe, "failed to get pod describe information")
		return resp, err
	}
	resp = &lcmservice.PodDescribeResponse{
		Response: r,
	}
	s.handleLoggingForSuccess(ctx, util.PodDescribe, "Pod description is successful")
	return resp, nil
}

// Query application
func (s *ServerGRPC) Query(ctx context.Context, req *lcmservice.QueryRequest) (resp *lcmservice.QueryResponse, err error) {

	resp = &lcmservice.QueryResponse{
		Response: util.Failure,
	}

	err = s.displayReceivedMsg(ctx, util.Query)
	if err != nil {
		s.displayResponseMsg(ctx, util.Query, util.FailedToDispRecvMsg)
		return resp, err
	}

	// Input validation
	hostIp, appInsId, err := s.validateInputParamsForQuery(req)
	if err != nil {
		s.displayResponseMsg(ctx, util.Query, util.FailedToValInputParams)
		return resp, err
	}

	// Get Client
	client, err := adapter.GetClient(util.DeployType, hostIp)
	if err != nil {
		s.displayResponseMsg(ctx, util.Query, util.FailedToGetClient)
		return resp, err
	}

	appInstanceRecord := &models.AppInstanceInfo{
		AppInsId: appInsId,
	}
	readErr := s.db.ReadData(appInstanceRecord, util.AppInsId)
	if readErr != nil {
		log.Error(util.AppRecordDoesNotExit)
		s.displayResponseMsg(ctx, util.Query, util.AppRecordDoesNotExit)
		return resp, err
	}

	// Query Chart
	r, err := client.Query(appInstanceRecord.WorkloadId)
	if err != nil {
		log.Errorf("Chart not found for workloadId: %s. Err: %s", appInstanceRecord.WorkloadId, err)
		s.displayResponseMsg(ctx, util.Query, "chart not found for workloadId")
		return resp, err
	}
	resp = &lcmservice.QueryResponse{
		Response: r,
	}
	s.handleLoggingForSuccess(ctx, util.Query, "Query pod statistics is successful")
	return resp, nil
}

// Terminate application
func (s *ServerGRPC) Terminate(ctx context.Context,
	req *lcmservice.TerminateRequest) (resp *lcmservice.TerminateResponse, err error) {

	resp = &lcmservice.TerminateResponse{
		Status: util.Failure,
	}

	err = s.displayReceivedMsg(ctx, util.Terminate)
	if err != nil {
		s.displayResponseMsg(ctx, util.Terminate, util.FailedToDispRecvMsg)
		return resp, err
	}

	hostIp, appInsId, err := s.validateInputParamsForTerm(req)
	if err != nil {
		s.displayResponseMsg(ctx, util.Terminate, util.FailedToValInputParams)
		return resp, err
	}
	appInstanceRecord := &models.AppInstanceInfo{
		AppInsId: appInsId,
	}
	readErr := s.db.ReadData(appInstanceRecord, util.AppInsId)
	if readErr != nil {
		log.Error(util.AppRecordDoesNotExit)
		s.displayResponseMsg(ctx, util.Terminate, util.AppRecordDoesNotExit)
		return resp, err
	}

	// Get Client
	client, err := adapter.GetClient(util.DeployType, hostIp)
	if err != nil {
		s.displayResponseMsg(ctx, util.Terminate, util.FailedToGetClient)
		return resp, err
	}

	// Uninstall chart
	err = client.UnDeploy(appInstanceRecord.WorkloadId)
	if err != nil {
		log.Errorf("Chart not found for workloadId: %s. Err: %s", appInstanceRecord.WorkloadId, err)
		s.displayResponseMsg(ctx, util.Terminate, "chart not found for workloadId")
		return resp, err
	}
	err = s.deleteAppInfoRecord(appInsId)
	if err != nil {
		s.displayResponseMsg(ctx, util.Terminate, "failed to delete app info record from database")
		return resp, err
	}
	resp = &lcmservice.TerminateResponse{
		Status: util.Success,
	}

	s.handleLoggingForSuccess(ctx, util.Terminate, "Termination is successful")
	return resp, nil
}

// Instantiate application
func (s *ServerGRPC) Instantiate(stream lcmservice.AppLCM_InstantiateServer) error {
	var res lcmservice.InstantiateResponse
	res.Status = util.Failure

	ctx := stream.Context()
	err := s.displayReceivedMsg(ctx, util.Instantiate)
	if err != nil {
		s.displayResponseMsg(ctx, util.Instantiate, util.FailedToDispRecvMsg)
		sendInstantiateResponse(stream, &res)
		return err
	}

	hostIp, appInsId, ak, sk, err := s.validateInputForInstantiation(stream)
	if err != nil {
		s.displayResponseMsg(ctx, util.Instantiate, util.FailedToValInputParams)
		sendInstantiateResponse(stream, &res)
		return err
	}

	pkg, err := s.getPackage(stream)
	if err != nil {
		s.displayResponseMsg(ctx, util.Instantiate, "failed to get package")
		sendInstantiateResponse(stream, &res)
		return err
	}

	// Get client
	client, err := adapter.GetClient(util.DeployType, hostIp)
	if err != nil {
		s.displayResponseMsg(ctx, util.Instantiate, util.FailedToGetClient)
		sendInstantiateResponse(stream, &res)
		return err
	}

	releaseName, err := client.Deploy(pkg, appInsId, ak, sk, s.db)
	if err != nil {
		log.Info("instantiation failed")
		s.displayResponseMsg(ctx, util.Instantiate, "instantiation failed")
		sendInstantiateResponse(stream, &res)
		return err
	}
	err = s.insertOrUpdateAppInsRecord(appInsId, hostIp, releaseName)
	if err != nil {
		s.displayResponseMsg(ctx, util.Instantiate, "failed to insert or update app record")
		sendInstantiateResponse(stream, &res)
		return err
	}
	log.Info("successful instantiation")
	res.Status = util.Success
	sendInstantiateResponse(stream, &res)
	s.handleLoggingForSuccess(ctx, util.Instantiate, "Instantiation is successful")
	return nil
}

// Upload file configuration
func (s *ServerGRPC) UploadConfig(stream lcmservice.AppLCM_UploadConfigServer) (err error) {
	var res lcmservice.UploadCfgResponse
	res.Status = util.Failure

	ctx := stream.Context()
	err = s.displayReceivedMsg(ctx, util.UploadConfig)
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, util.FailedToDispRecvMsg)
		sendUploadCfgResponse(stream, &res)
		return err
	}

	hostIp, err := s.validateInputParamsForUploadCfg(stream)
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, util.FailedToValInputParams)
		sendUploadCfgResponse(stream, &res)
		return
	}

	file, err := s.getUploadConfigFile(stream)
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, "failed to get upload config file")
		sendUploadCfgResponse(stream, &res)
		return err
	}

	if !util.CreateDir(KubeconfigPath) {
		s.displayResponseMsg(ctx, util.UploadConfig, "failed to create config directory")
		sendUploadCfgResponse(stream, &res)
		return err
	}

	configPath := KubeconfigPath + hostIp
	newFile, err := os.Create(configPath)
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, "failed to create config path")
		sendUploadCfgResponse(stream, &res)
		return err
	}

	if len(file.Bytes()) > util.MaxConfigFile {
		s.displayResponseMsg(ctx, util.UploadConfig, "file size is larger than max size")
		sendUploadCfgResponse(stream, &res)
		return err
	}

	defer newFile.Close()
	_, err = newFile.Write(file.Bytes())
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, "config IO operation error")
		sendUploadCfgResponse(stream, &res)
		return err
	}

	res.Status = util.Success
	sendUploadCfgResponse(stream, &res)
	s.handleLoggingForSuccess(ctx, util.UploadConfig, "Upload config is successful")
	return nil
}

// Remove file configuration
func (s *ServerGRPC) RemoveConfig(ctx context.Context,
	request *lcmservice.RemoveCfgRequest) (*lcmservice.RemoveCfgResponse, error) {

	resp := &lcmservice.RemoveCfgResponse{
		Status: util.Failure,
	}

	err := s.displayReceivedMsg(ctx, util.RemoveConfig)
	if err != nil {
		s.displayResponseMsg(ctx, util.RemoveConfig, util.FailedToDispRecvMsg)
		return resp, err
	}

	hostIp, err := s.validateInputParamsForRemoveCfg(request)
	if err != nil {
		s.displayResponseMsg(ctx, util.RemoveConfig, util.FailedToValInputParams)
		return resp, err
	}
	configPath := KubeconfigPath + hostIp
	err = os.Remove(configPath)
	if err != nil {
		log.Error("failed to remove host config file")
		s.displayResponseMsg(ctx, util.RemoveConfig, "failed to remove host config file")
		return resp, err
	}

	resp = &lcmservice.RemoveCfgResponse{
		Status: util.Success,
	}
	s.handleLoggingForSuccess(ctx, util.UploadConfig, "Remove config is successful")
	return resp, nil
}

// Validate input parameters for remove config
func (s *ServerGRPC) validateInputParamsForRemoveCfg(request *lcmservice.RemoveCfgRequest) (string, error) {
	accessToken := request.GetAccessToken()
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		if err.Error() == util.Forbidden {
			return "", s.logError(status.Error(codes.PermissionDenied, util.Forbidden))
		} else {
			return "", s.logError(status.Error(codes.InvalidArgument, util.AccssTokenIsInvalid))
		}
	}
	hostIp := request.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", s.logError(status.Error(codes.InvalidArgument, util.HostIpIsInvalid))
	}
	return hostIp, nil
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
func (s *ServerGRPC) validateInputForInstantiation(stream lcmservice.AppLCM_InstantiateServer) (string, string,
	string, string, error) {
	// Receive metadata which is access token
	req, err := stream.Recv()
	if err != nil {
		return "", "", "", "", s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}
	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		if err.Error() == util.Forbidden {
			return "", "", "", "", s.logError(status.Error(codes.PermissionDenied, util.Forbidden))
		} else {
			return "", "", "", "", s.logError(status.Error(codes.InvalidArgument, util.AccssTokenIsInvalid))
		}
	}

	// Receive metadata which is ak
	req, err = stream.Recv()
	if err != nil {
		return "", "", "", "", s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}
	ak := req.GetAk()
	err = util.ValidateAk(ak)
	if err != nil {
		return "", "", "", "", s.logError(status.Error(codes.InvalidArgument, "ak length is invalid"))
	}

	// Receive metadata which is sk
	req, err = stream.Recv()
	if err != nil {
		return "", "", "", "", s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}
	sk := req.GetSk()
	err = util.ValidateSk(sk)
	if err != nil {
		return "", "", "", "", s.logError(status.Error(codes.InvalidArgument, "sk length is invalid"))
	}

	// Receive metadata which is app instance id
	req, err = stream.Recv()
	if err != nil {
		return "", "", "", "", s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}
	appInsId := req.GetAppInstanceId()
	err = util.ValidateUUID(appInsId)
	if err != nil {
		return "", "", "", "", s.logError(status.Error(codes.InvalidArgument, "app instance id is invalid"))
	}

	// Receive metadata which is host ip
	req, err = stream.Recv()
	if err != nil {
		return "", "", "", "", s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}
	hostIp := req.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", "", "", "", s.logError(status.Error(codes.InvalidArgument, util.HostIpIsInvalid))
	}

	return hostIp, appInsId, ak, sk, nil
}

// Validate input parameters for termination
func (s *ServerGRPC) validateInputParamsForTerm(
	req *lcmservice.TerminateRequest) (hostIp string, appInsId string, err error) {
	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		if err.Error() == util.Forbidden {
			return "", "", s.logError(status.Error(codes.PermissionDenied, util.Forbidden))
		} else {
			return "", "", s.logError(status.Error(codes.InvalidArgument,
				util.AccssTokenIsInvalid))
		}
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
			util.AppInsIdValid))
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
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		if err.Error() == util.Forbidden {
			return "", s.logError(status.Error(codes.PermissionDenied, util.Forbidden))
		} else {
			return "", s.logError(status.Error(codes.InvalidArgument, util.AccssTokenIsInvalid))
		}
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

// Validate input parameters for pod describe
func (s *ServerGRPC) validateInputParamsForPodDesc(
	req *lcmservice.PodDescribeRequest) (hostIp string, podName string, err error) {

	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole, util.MecmGuestRole})
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument,
			util.AccssTokenIsInvalid))
	}

	hostIp = req.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument, util.HostIpIsInvalid))
	}

	appInsId := req.GetAppInstanceId()
	err = util.ValidateUUID(appInsId)
	if err != nil {
		return "", "", s.logError(status.Error(codes.InvalidArgument, util.AppInsIdValid))
	}

	return hostIp, appInsId, nil
}

// Validate input parameters for Query
func (s *ServerGRPC) validateInputParamsForQuery(
	req *lcmservice.QueryRequest) (hostIp string, appInsId string, err error) {

	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmGuestRole, util.MecmAdminRole})
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
		return "", "", s.logError(status.Error(codes.InvalidArgument, util.AppInsIdValid))
	}

	return hostIp, appInsId, nil
}

// Get package
func (s *ServerGRPC) getPackage(stream lcmservice.AppLCM_InstantiateServer) (buf bytes.Buffer, err error) {
	// Receive package
	pkg := bytes.Buffer{}
	for {
		err := s.contextError(stream.Context())
		if err != nil {
			return pkg, err
		}

		log.Debug("Waiting to receive more data")

		req, err := stream.Recv()
		if err == io.EOF {
			log.Debug("No more data")
			break
		}
		if err != nil {
			return pkg, s.logError(status.Error(codes.Unknown, "cannot receive chunk data"))
		}

		// Receive chunk and write to package
		chunk := req.GetPackage()

		_, err = pkg.Write(chunk)
		if err != nil {
			return pkg, s.logError(status.Error(codes.Internal, "cannot write chunk data"))
		}
	}
	return pkg, nil
}

// Get upload configuration file
func (s *ServerGRPC) getUploadConfigFile(stream lcmservice.AppLCM_UploadConfigServer) (but bytes.Buffer, err error) {
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
			return file, s.logError(status.Error(codes.Unknown, "cannot receive chunk data"))
		}

		// Receive chunk and write to package
		chunk := req.GetConfigFile()

		_, err = file.Write(chunk)
		if err != nil {
			return file, s.logError(status.Error(codes.Internal, "cannot write chunk data"))
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
			"failed to save app info record to database."))
	}
	return nil
}

// Delete app instance record
func (s *ServerGRPC) deleteAppInfoRecord(appInsId string) error {
	appInfoRecord := &models.AppInstanceInfo{
		AppInsId: appInsId,
	}

	err := s.db.DeleteData(appInfoRecord, util.AppInsId)
	if err != nil {
		return s.logError(status.Error(codes.InvalidArgument,
			"failed to delete app info record from database"))
	}
	return nil
}

// display response message
func (s *ServerGRPC) handleLoggingForSuccess(ctx context.Context, rpcName string, msg string) {
	clientIp, err := s.getClientAddress(ctx)
	if err != nil {
		return
	}

	log.Info("Response message for ClientIP [" + clientIp + "]" +
		util.RpcName + rpcName + "] Result [Success: " + msg + ".]")
}

// Display received message
func (s *ServerGRPC) displayReceivedMsg(ctx context.Context, rpcName string) error {
	clientIp, err := s.getClientAddress(ctx)
	if err != nil {
		return err
	}

	log.Info("Received message from ClientIP [" + clientIp + "]" + util.RpcName + rpcName + "]")
	return nil
}

// display response message
func (s *ServerGRPC) displayResponseMsg(ctx context.Context, rpcName string, errMsg string) {
	clientIp, err := s.getClientAddress(ctx)
	if err != nil {
		return
	}

	log.Info("Response message for ClientIP [" + clientIp + "]" +
		util.RpcName + rpcName + "] Result [Failure: " + errMsg + ".]")
}

// Get client address
func (s *ServerGRPC) getClientAddress(ctx context.Context) (remoteIp string, err error) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return "",  s.logError(status.Errorf(codes.NotFound, "failed to get peer from ctx"))
	}
	if pr.Addr == net.Addr(nil) {
		return "",  s.logError(status.Errorf(codes.NotFound, "failed to get peer address"))
	}
	clientAddr := pr.Addr.String()
	clientIp := strings.Split(clientAddr, ":")
	return clientIp[0], nil
}

// Send instantiate response
func sendInstantiateResponse(stream lcmservice.AppLCM_InstantiateServer,
	res *lcmservice.InstantiateResponse) {
	err := stream.SendAndClose(res)
	if err != nil {
		log.Errorf("cannot send response: %v", err)
		return
	}
}

// Send upload config response
func sendUploadCfgResponse(stream lcmservice.AppLCM_UploadConfigServer,
	res *lcmservice.UploadCfgResponse) {
	err := stream.SendAndClose(res)
	if err != nil {
		log.Errorf("cannot send response: %v", err)
		return
	}
}