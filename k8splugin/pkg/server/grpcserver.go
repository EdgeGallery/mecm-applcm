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
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/tap"
	"io"
	"io/ioutil"
	"k8splugin/conf"
	"k8splugin/internal/lcmservice"
	"k8splugin/models"
	"k8splugin/pgdb"
	"k8splugin/pkg/adapter"
	"k8splugin/util"
	"net"
	"os"
	"path"
	"path/filepath"
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
	appPackagesBasePath = "/usr/app/packages/"
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
func (s *ServerGRPC) WorkloadEvents(ctx context.Context, req *lcmservice.WorkloadEventsRequest) (resp *lcmservice.WorkloadEventsResponse, err error) {

	resp = &lcmservice.WorkloadEventsResponse{
		Response: util.Failure,
	}

	err = s.displayReceivedMsg(ctx, util.WorkloadEvents)
	if err != nil {
		s.displayResponseMsg(ctx, util.WorkloadEvents, util.FailedToDispRecvMsg)
		return resp, err
	}

	// Input validation
	hostIp, appInsId, err := s.validateInputParamsForPodDesc(req)
	if err != nil {
		s.displayResponseMsg(ctx, util.WorkloadEvents, util.FailedToValInputParams)
		return resp, err
	}

	// Get Client
	client, err := adapter.GetClient(util.DeployType, hostIp)
	if err != nil {
		s.displayResponseMsg(ctx, util.WorkloadEvents, util.FailedToGetClient)
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
	r, err := client.WorkloadEvents(appInstanceRecord.WorkloadId)
	if err != nil {
		s.displayResponseMsg(ctx, util.WorkloadEvents, "failed to get pod describe information")
		return resp, err
	}
	resp = &lcmservice.WorkloadEventsResponse{
		Response: r,
	}
	s.handleLoggingForSuccess(ctx, util.WorkloadEvents, "Pod description is successful")
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



func (s *ServerGRPC) Instantiate(ctx context.Context,
	req *lcmservice.InstantiateRequest) (resp *lcmservice.InstantiateResponse, err error) {

	resp = &lcmservice.InstantiateResponse{
		Status: util.Failure,
	}

	err = s.displayReceivedMsg(ctx, util.Instantiate)
	if err != nil {
		s.displayResponseMsg(ctx, util.Instantiate, util.FailedToDispRecvMsg)
		return resp, err
	}

	tenantId, packageId, hostIp, appInsId, ak, sk, err := s.validateInputParamsForInstantiate(req)
	if err != nil {
		s.displayResponseMsg(ctx, util.Instantiate, util.FailedToValInputParams)
		return resp, err
	}
	appPkgRecord := &models.AppPackage{
		AppPkgId: packageId + tenantId + hostIp,
	}
	readErr := s.db.ReadData(appPkgRecord, util.AppPkgId)
	if readErr != nil {
		log.Error(util.AppPkgRecordDoesNotExit)
		s.displayResponseMsg(ctx, util.Instantiate, util.AppPkgRecordDoesNotExit)
		return resp, err
	}

	// Get Client
	client, err := adapter.GetClient(util.DeployType, hostIp)
	if err != nil {
		s.displayResponseMsg(ctx, util.Instantiate, util.FailedToGetClient)
		return resp, err
	}

	releaseName, err := client.Deploy(tenantId, hostIp, packageId, appInsId, ak, sk, s.db)
	if err != nil {
		log.Info("instantiation failed")
		s.displayResponseMsg(ctx, util.Instantiate, "instantiation failed")
		return resp, err
	}
	err = s.insertOrUpdateAppInsRecord(appInsId, hostIp, releaseName)
	if err != nil {
		s.displayResponseMsg(ctx, util.Instantiate, "failed to insert or update app record")
		return resp, err
	}
	log.Info("successful instantiation")
	resp.Status = util.Success
	s.handleLoggingForSuccess(ctx, util.Instantiate, "Application instantiated successfully")
	return resp, nil
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

// Validate input parameters for termination
func (s *ServerGRPC) validateInputParamsForInstantiate(
	req *lcmservice.InstantiateRequest) (tenantId string, packageId string, hostIp string, appInsId string, ak string, sk string, err error) {
	accessToken := req.GetAccessToken()
	err = util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		if err.Error() == util.Forbidden {
			return "", "", "", "",  "", "", s.logError(status.Error(codes.PermissionDenied, util.Forbidden))
		} else {
			return "", "", "", "",  "", "", s.logError(status.Error(codes.InvalidArgument,
				util.AccssTokenIsInvalid))
		}
	}

	hostIp = req.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", "", "", "",  "", "", s.logError(status.Error(codes.InvalidArgument,
			util.HostIpIsInvalid))
	}

	packageId = req.GetAppPackageId()
	if packageId == "" {
		return "", "", "", "",  "", "", s.logError(status.Error(codes.InvalidArgument,
			util.PackageIdIsInvalid))
	}

	tenantId = req.GetTenantId()
	err = util.ValidateUUID(tenantId)
	if err != nil {
		return "", "", "", "",  "", "", s.logError(status.Error(codes.InvalidArgument,
			util.TenantIdIsInvalid))
	}

	ak = req.GetAk()
	if ak == "" {
		return "", "", "", "",  "", "", s.logError(status.Error(codes.InvalidArgument,
			util.AKIsInvalid))
	}

	sk = req.GetSk()
	if sk == "" {
		return "", "", "", "",  "", "", s.logError(status.Error(codes.InvalidArgument,
			util.SKIsInvalid))
	}

	appInsId = req.GetAppInstanceId()
	err = util.ValidateUUID(appInsId)
	if err != nil {
		return "", "", "", "", "", "", s.logError(status.Error(codes.InvalidArgument,
			util.AppInsIdValid))
	}

	return tenantId, packageId, hostIp, appInsId, ak, sk, nil
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
	req *lcmservice.WorkloadEventsRequest) (hostIp string, podName string, err error) {

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

// Insert or update application package record
func (s *ServerGRPC) insertOrUpdateAppPkgRecord(packageId string, tenantId string,
	hostIp string, dockerImages string) (err error) {
	appPkgRecord := &models.AppPackage{
		AppPkgId:     packageId + tenantId + hostIp,
		HostIp:       hostIp,
		TenantId:     tenantId,
		DockerImages: dockerImages,
	}
	err = s.db.InsertOrUpdateData(appPkgRecord, util.AppPkgId)
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

// Delete app instance record
func (s *ServerGRPC) deleteAppPackageRecord(appPkgId, tenantId, hostIp string) error {
	appPkgRecord := &models.AppPackage{
		AppPkgId: appPkgId + tenantId + hostIp,
	}

	err := s.db.DeleteData(appPkgRecord, util.AppPkgId)
	if err != nil {
		return s.logError(status.Error(codes.InvalidArgument,
			"failed to delete app package record from database"))
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

// Send upload config response
func sendUploadCfgResponse(stream lcmservice.AppLCM_UploadConfigServer,
	res *lcmservice.UploadCfgResponse) {
	err := stream.SendAndClose(res)
	if err != nil {
		log.Errorf("cannot send response: %v", err)
		return
	}
}

// Upload file configuration
func (s *ServerGRPC) UploadPackage(stream lcmservice.AppLCM_UploadPackageServer) (err error) {
	var res lcmservice.UploadPackageResponse
	res.Status = util.Failure

	ctx := stream.Context()
	err = s.displayReceivedMsg(ctx, util.UploadPackage)
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadPackage, util.FailedToDispRecvMsg)
		sendUploadPackageResponse(stream, &res)
		return err
	}

	hostIp, tenantId, packageId, err := s.validateInputParamsForUploadPackage(stream)
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, util.FailedToValInputParams)
		sendUploadPackageResponse(stream, &res)
		return
	}

	file, err := s.getUploadPackageFile(stream)
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, "failed to get upload package file")
		sendUploadPackageResponse(stream, &res)
		return err
	}

	if !util.CreateDir(appPackagesBasePath + tenantId) {
		s.displayResponseMsg(ctx, util.UploadConfig, "failed to create package directory")
		sendUploadPackageResponse(stream, &res)
		return err
	}

	packagePath := appPackagesBasePath + tenantId + "/" + packageId + hostIp
	if !util.CreateDir(packagePath) {
		s.displayResponseMsg(ctx, util.UploadConfig, "failed to create config directory")
		sendUploadPackageResponse(stream, &res)
		return err
	}

	packageFilePath := packagePath + "/" + packageId + ".csar"
	newFile, err := os.Create(packageFilePath)
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, "failed to create application package path")
		sendUploadPackageResponse(stream, &res)
		return err
	}

	if len(file.Bytes()) > util.MaxPackageFile {
		s.displayResponseMsg(ctx, util.UploadConfig, "package size is larger than max size")
		sendUploadPackageResponse(stream, &res)
		return err
	}

	defer newFile.Close()
	_, err = newFile.Write(file.Bytes())
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, "package IO operation error")
		sendUploadPackageResponse(stream, &res)
		return err
	}

	packagePath, err = s.extractCsarPackage(packageFilePath)
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, "failed to extract csar app package")
		sendUploadPackageResponse(stream, &res)
		return err
	}

	dockerImages, err := s.loadDockerImagesToHost(packagePath)
	if err != nil {
		s.displayResponseMsg(ctx, util.UploadConfig, "failed to process SwImageDescr")
		sendUploadPackageResponse(stream, &res)
		return err
	}

	err = s.insertOrUpdateAppPkgRecord(packageId, tenantId, hostIp, dockerImages)
	if err != nil {
		s.displayResponseMsg(ctx, util.Instantiate, "failed to insert or update app package record")
		sendUploadPackageResponse(stream, &res)
		return err
	}

	res.Status = util.Success
	sendUploadPackageResponse(stream, &res)
	s.handleLoggingForSuccess(ctx, util.UploadConfig, "Uploaded package successfully")
	return nil
}

// Send upload config response
func sendUploadPackageResponse(stream lcmservice.AppLCM_UploadPackageServer,
	res *lcmservice.UploadPackageResponse) {
	err := stream.SendAndClose(res)
	if err != nil {
		log.Errorf("cannot send response: %v", err)
		return
	}
}

// Validate input parameters for upload configuration
func (s *ServerGRPC) validateInputParamsForUploadPackage(
	stream lcmservice.AppLCM_UploadPackageServer) (hostIp, tenantId, packageId string, err error) {
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
			return "", "", "",  s.logError(status.Error(codes.PermissionDenied, util.Forbidden))
		} else {
			return "", "", "",  s.logError(status.Error(codes.InvalidArgument, util.AccssTokenIsInvalid))
		}
	}

	// Receive metadata which is package ID
	req, err = stream.Recv()
	if err != nil {
		log.Error(util.CannotReceivePackage)
		return "", "", "",  s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}

	packageId = req.GetAppPackageId()
	if packageId == "" {
		return "", "", "", s.logError(status.Error(codes.InvalidArgument, util.PackageIdIsInvalid))
	}

	// Receive metadata which is host ip
	req, err = stream.Recv()
	if err != nil {
		log.Error(util.CannotReceivePackage)
		return "", "", "",  s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}

	hostIp = req.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", "", "",  s.logError(status.Error(codes.InvalidArgument, util.HostIpIsInvalid))
	}

	// Receive metadata which is tenant ID
	req, err = stream.Recv()
	if err != nil {
		log.Error(util.CannotReceivePackage)
		return "", "", "",  s.logError(status.Error(codes.InvalidArgument, util.CannotReceivePackage))
	}
	tenantId = req.GetTenantId()
	err = util.ValidateUUID(tenantId)
	if err != nil {
		return "", "", "",  s.logError(status.Error(codes.InvalidArgument, util.TenantIsInvalid))
	}

	return hostIp, tenantId, packageId, nil
}

// Get upload package file
func (s *ServerGRPC) getUploadPackageFile(stream lcmservice.AppLCM_UploadPackageServer) (but bytes.Buffer, err error) {
	// Receive upload package file
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
		chunk := req.GetPackage()

		_, err = file.Write(chunk)
		if err != nil {
			return file, s.logError(status.Error(codes.Internal, "cannot write chunk data"))
		}
	}
	return file, nil
}

// Delete application package
func (s *ServerGRPC) DeletePackage(ctx context.Context,
	request *lcmservice.DeletePackageRequest) (*lcmservice.DeletePackageResponse, error) {

	resp := &lcmservice.DeletePackageResponse{
		Status: util.Failure,
	}

	err := s.displayReceivedMsg(ctx, util.DeletePackage)
	if err != nil {
		s.displayResponseMsg(ctx, util.DeletePackage, util.FailedToDispRecvMsg)
		return resp, err
	}

	//tenantId, hostIp, packageId, err := s.validateInputParamsForDeletePackage(request)
	tenantId, hostIp, packageId, err := s.validateInputParamsForDeletePackage(request)
	if err != nil {
		s.displayResponseMsg(ctx, util.DeletePackage, util.FailedToValInputParams)
		return resp, err
	}

	appPkgRecord, err := s.getAppPackageRecord(hostIp, packageId, tenantId)
	if err != nil {
		log.Error(util.AppPkgRecordDoesNotExit)
		s.displayResponseMsg(ctx, util.DeletePackage, util.AppPkgRecordDoesNotExit)
		return resp, err
	}

	err = s.deleteAppPackageRecord(packageId, tenantId, hostIp)
	if err != nil {
		s.displayResponseMsg(ctx, util.Terminate, "failed to delete app package record from database")
		return resp, err
	}

	_ = s.deleteDockerImagesFromHost(appPkgRecord.DockerImages)

	packagePath := appPackagesBasePath + tenantId + "/" + packageId + appPkgRecord.HostIp
	err = s.deletePackage(packagePath)
	if err != nil {
		log.Error("failed to delete application package file")
		s.displayResponseMsg(ctx, util.DeletePackage, "failed to delete application package")
		return resp, nil
	}
	
	resp = &lcmservice.DeletePackageResponse{
		Status: util.Success,
	}
	s.handleLoggingForSuccess(ctx, util.DeletePackage, "Deleted application package successfully")
	return resp, nil
}

func (s *ServerGRPC) deletePackage(appPkgPath string) error {

	tenantPath := path.Dir(appPkgPath)

	//remove package directory
	err := os.RemoveAll(appPkgPath)
	if err != nil {
		return errors.New("failed to delete application package file")
	}

	tenantDir, err := os.Open(tenantPath)
	if err != nil {
		return errors.New("failed to delete application package")
	}
	defer tenantDir.Close()
	
	_, err = tenantDir.Readdir(1)
	
	if err == io.EOF {
		err := os.Remove(tenantPath)
		if err != nil {
            return errors.New("failed to delete application package")
		}
		return nil
	}
	return nil
}

// Validate input parameters for remove config
func (s *ServerGRPC) validateInputParamsForDeletePackage(request *lcmservice.DeletePackageRequest) (string,
	string, string, error) {
	accessToken := request.GetAccessToken()
	err := util.ValidateAccessToken(accessToken, []string{util.MecmTenantRole, util.MecmAdminRole})
	if err != nil {
		if err.Error() == util.Forbidden {
			return "", "", "",  s.logError(status.Error(codes.PermissionDenied, util.Forbidden))
		} else {
			return "", "", "",  s.logError(status.Error(codes.InvalidArgument, util.AccssTokenIsInvalid))
		}
	}
	hostIp := request.GetHostIp()
	err = util.ValidateIpv4Address(hostIp)
	if err != nil {
		return "", "", "",  s.logError(status.Error(codes.InvalidArgument, util.HostIpIsInvalid))
	}

	packageId := request.GetAppPackageId()
	if packageId == "" {
		return "", "", "",  s.logError(status.Error(codes.InvalidArgument, util.HostIpIsInvalid))
	}

	tenantId := request.GetTenantId()
	err = util.ValidateUUID(tenantId)
	if err != nil {
		return "", "", "", s.logError(status.Error(codes.InvalidArgument, util.HostIpIsInvalid))
	}
	return tenantId, hostIp, packageId, nil
}

// extract CSAR package
func (c *ServerGRPC) extractCsarPackage(packagePath string) (string, error) {
	zipReader, _ := zip.OpenReader(packagePath)
	if len(zipReader.File) > util.TooManyFile {
		return "", errors.New("Too many files contains in zip file")
	}
	var totalWrote int64
	packageDir := path.Dir(packagePath)
	err := os.MkdirAll(packageDir, 0750)
	if err != nil {
		log.Error("Failed to make directory")
		return "" ,errors.New("Failed to make directory")
	}
	for _, file := range zipReader.Reader.File {

		zippedFile, err := file.Open()
		if err != nil || zippedFile == nil {
			log.Error("Failed to open zip file")
			continue
		}
		if file.UncompressedSize64 > util.SingleFileTooBig || totalWrote > util.TooBig {
			log.Error("File size limit is exceeded")
		}

		defer zippedFile.Close()

		isContinue, wrote := c.extractFiles(file, zippedFile, totalWrote, packageDir)
		if isContinue {
			continue
		}
		totalWrote = wrote
	}
	return packageDir, nil
}

// Extract files
func (c *ServerGRPC) extractFiles(file *zip.File, zippedFile io.ReadCloser, totalWrote int64, dirName string) (bool, int64) {
	targetDir := dirName
	extractedFilePath := filepath.Join(
		targetDir,
		file.Name,
	)

	if file.FileInfo().IsDir() {
		err := os.MkdirAll(extractedFilePath, 0750)
		if err != nil {
			log.Error("Failed to create directory")
		}
	} else {
		outputFile, err := os.OpenFile(
			extractedFilePath,
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
			0750,
		)
		if err != nil || outputFile == nil {
			log.Error("The output file is nil")
			return true, totalWrote
		}

		defer outputFile.Close()

		wt, err := io.Copy(outputFile, zippedFile)
		if err != nil {
			log.Error("Failed to copy zipped file")
		}
		totalWrote += wt
	}
	return false, totalWrote
}

func (s *ServerGRPC) deleteDockerImagesFromHost(dockerImages string) error {
    log.Info("Delete docker images")
	dockers := strings.Split(dockerImages, ",")
	for i := range dockers {
		log.WithFields(log.Fields{
			"delete docker image": dockers[i],
		}).Info("delete docker images")

		//TODO: delete docker images form host machine using docker client
	}
	return nil
}

// get sw image descriptors
func (c *ServerGRPC) loadDockerImagesToHost(packagePath string) (string, error) {

	var imageDescriptors []models.SwImageDescriptor

	jsonFile, err := os.Open(packagePath + "/Image/SwImageDesc.json")
	if err != nil {
		return "", errors.New("failed to get SwImageDesc.json")
	}
	defer jsonFile.Close()

	imageDescrBytes, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(imageDescrBytes, &imageDescriptors)

	dockerImages := make([]string, 0)
	for i := range imageDescriptors {
		log.WithFields(log.Fields{
			"loading docker image": imageDescriptors[i].SwImage,
		}).Info("load docker images")

		dockerImages = append(dockerImages, imageDescriptors[i].SwImage)

		//TODO: load docker image to docker host using docker client
	}

	return strings.Join(dockerImages,", "), nil
}

// Get app package record
func (c *ServerGRPC) getAppPackageRecord(hostIp, appPkgId, tenantId string) (*models.AppPackage, error) {
	appPkgRecord := &models.AppPackage{
		AppPkgId: appPkgId + tenantId + hostIp,
	}

	readErr := c.db.ReadData(appPkgRecord, util.AppPkgId)
	if readErr != nil {
		log.Error(util.AppPkgRecordDoesNotExit)
		return nil, readErr
	}
	return appPkgRecord, nil
}

