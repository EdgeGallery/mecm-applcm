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

package pluginAdapter

import (
	"bytes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"io"
	"lcmcontroller/internal/lcmservice"
	"lcmcontroller/models"
	"lcmcontroller/util"
	"mime/multipart"
	"os"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
)

// GRPC client to different GRPC supported plugins
type ClientGRPC struct {
	conn        *grpc.ClientConn
	client      lcmservice.AppLCMClient
	imageClient lcmservice.VmImageClient
	chunkSize   int
}

// GRPC client configuration
type ClientGRPCConfig struct {
	Address         string
	ChunkSize       int
	RootCertificate string
}

// Create a GRPC client
func NewClientGRPC(cfg ClientGRPCConfig) (c *ClientGRPC, err error) {

	var (
		grpcOpts []grpc.DialOption
		conn     *grpc.ClientConn
	)

	if util.GetAppConfig("client_ssl_enable") == "true" {

		tlsConfig, err := util.TLSConfig(cfg.RootCertificate)
		if err != nil {
			log.Error("failed to get TLS configuration with error")
			return nil, err
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

	return &ClientGRPC{chunkSize: cfg.ChunkSize, conn: conn, client: lcmservice.NewAppLCMClient(conn),
		imageClient: lcmservice.NewVmImageClient(conn)}, nil
}

// Instantiate application
func (c *ClientGRPC) Instantiate(ctx context.Context, tenantId string, accessToken string,
	appInsId string, instantiateReq models.InstantiateRequest) (status string, error error) {
	req := &lcmservice.InstantiateRequest{
		HostIp:        instantiateReq.HostIp,
		TenantId:      tenantId,
		AppPackageId:  instantiateReq.PackageId,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		Parameters: instantiateReq.Parameters,
		AkSkLcmGen: instantiateReq.AkSkLcmGen,
	}
	resp, err := c.client.Instantiate(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Query application
func (c *ClientGRPC) Query(ctx context.Context, accessToken string,
	appInsId string, hostIP string) (response string, error error) {

	req := &lcmservice.QueryRequest{
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		HostIp:        hostIP,
	}
	resp, err := c.client.Query(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Query application
func (c *ClientGRPC) QueryKPI(ctx context.Context, accessToken, hostIP string) (response string, error error) {

	req := &lcmservice.QueryKPIRequest{
		AccessToken:   accessToken,
		HostIp:        hostIP,
	}
	resp, err := c.client.QueryKPI(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Terminate application
func (c *ClientGRPC) Terminate(ctx context.Context, hostIP string, accessToken string,
	appInsId string) (status string, error error) {

	req := &lcmservice.TerminateRequest{
		HostIp:        hostIP,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
	}
	resp, err := c.client.Terminate(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Remove configuration
func (c *ClientGRPC) RemoveConfig(ctx context.Context, hostIP string, accessToken string) (status string, error error) {
	req := &lcmservice.RemoveCfgRequest{
		HostIp:      hostIP,
		AccessToken: accessToken,
	}
	resp, err := c.client.RemoveConfig(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

// Upload Configuration
func (c *ClientGRPC) UploadConfig(ctx context.Context, multipartFile multipart.File,
	hostIP string, accessToken string) (status string, error error) {
	var (
		writing = true
		buf     []byte
		n       int
	)

	// Open a stream-based connection with the
	// gRPC server
	stream, err := c.client.UploadConfig(ctx)
	if err != nil {
		log.Error("failed to upload stream")
		return util.Failure, err
	}
	defer stream.CloseSend()

	//send metadata information
	req := &lcmservice.UploadCfgRequest{

		Data: &lcmservice.UploadCfgRequest_AccessToken{
			AccessToken: accessToken,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Error(util.FailedToSendMetadataInfo)
		return util.Failure, err
	}

	//send metadata information
	req = &lcmservice.UploadCfgRequest{

		Data: &lcmservice.UploadCfgRequest_HostIp{
			HostIp: hostIP,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Error(util.FailedToSendMetadataInfo)
		return util.Failure, err
	}

	// Allocate a buffer with `chunkSize` as the capacity
	// and length (making a 0 array of the size of `chunkSize`)
	buf = make([]byte, c.chunkSize)
	for writing {
		// put as many bytes as `chunkSize` into the
		// buf array.
		n, err = multipartFile.Read(buf)
		if err != nil {
			// ... if `eof` --> `writing=false`...
			if err == io.EOF {
				writing = false
				continue
			}
			log.Error("failed while copying from file to buf")
			return util.Failure, err
		}

		req := &lcmservice.UploadCfgRequest{
			Data: &lcmservice.UploadCfgRequest_ConfigFile{
				ConfigFile: buf[:n],
			},
		}

		err = stream.Send(req)

		if err != nil {
			log.Error("failed to send chunk via stream")
			return util.Failure, err
		}
	}

	res, err := stream.CloseAndRecv()
	if err != nil {
		log.Error("received upstream status response")
		return util.Failure, err
	}
	return res.GetStatus(), err
}

// Get workload description
func (c *ClientGRPC) WorkloadDescription(ctx context.Context, accessToken string,
	appInsId string, hostIP string) (response string, error error) {

	req := &lcmservice.WorkloadEventsRequest{
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		HostIp:        hostIP,
	}
	resp, err := c.client.WorkloadEvents(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Create VM Image
func (c *ClientGRPC) CreateVmImage(ctx context.Context, accessToken string, appInsId string,
	hostIP string, vmId string) (response string, error error) {
	req := &lcmservice.CreateVmImageRequest{
		HostIp:        hostIP,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		VmId:          vmId,
	}
	resp, err := c.imageClient.CreateVmImage(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Query VM Image
func (c *ClientGRPC) QueryVmImage(ctx context.Context, accessToken string, appInsId string,
	hostIP string, imageId string) (response string, error error) {
	req := &lcmservice.QueryVmImageRequest{
		HostIp:        hostIP,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		ImageId:       imageId,
	}
	resp, err := c.imageClient.QueryVmImage(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Delete VM Image
func (c *ClientGRPC) DeleteVmImage(ctx context.Context, accessToken string, appInsId string,
	hostIP string, imageId string) (response string, error error) {
	req := &lcmservice.DeleteVmImageRequest{
		HostIp:        hostIP,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		ImageId:       imageId,
	}
	resp, err := c.imageClient.DeleteVmImage(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Response, err
}

// Download VM Image
func (c *ClientGRPC) DownloadVmImage(ctx context.Context, accessToken string, appInsId string,
	hostIP string, imageId string, chunkNum int32) (buf *bytes.Buffer, error error) {
	req := &lcmservice.DownloadVmImageRequest{
		HostIp:        hostIP,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		ImageId:       imageId,
		ChunkNum:      chunkNum,
	}


	stream, err := c.imageClient.DownloadVmImage(ctx, req)
	if err != nil {
		return buf, err
	}
	var count int32 = 0
	for {
		err := c.contextError(stream.Context())
		if err != nil {
			return buf, err
		}

		log.Debug("Waiting to receive more data")

		res, err := stream.Recv()
		if err == io.EOF {
			log.Info("No more data")
			break
		}
		if err != nil {
			return buf, c.logError(status.Error(codes.Unknown, "cannot receive chunk data"))
		}

		// Receive chunk and write to package
		chunk := res.GetContent()
		util.VmImageMap[count] = chunk
		count++
	}
	_ = stream.CloseSend()
	return buf, nil
}

// Close connection
func (c *ClientGRPC) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// Context Error
func (c *ClientGRPC) contextError(ctx context.Context) error {
	switch ctx.Err() {
	case context.Canceled:
		return c.logError(status.Error(codes.Canceled, "request is canceled"))
	case context.DeadlineExceeded:
		return c.logError(status.Error(codes.DeadlineExceeded, "deadline is exceeded"))
	default:
		return nil
	}
}

// Logging error
func (c *ClientGRPC) logError(err error) error {
	if err != nil {
		log.Errorf("Error Information: %v", err)
	}
	return err
}

// Upload application package
func (c *ClientGRPC) UploadPackage(ctx context.Context, tenantId string, appPkg string,
	hostIP string, packageId string, accessToken string) (status string, error error) {
	var (
		writing = true
		buf     []byte
		n       int
		file    *os.File
	)

	// Open a stream-based connection with the
	// gRPC server
	stream, err := c.client.UploadPackage(ctx)
	if err != nil {
		log.Error("failed to upload stream")
		return util.Failure, err
	}
	defer stream.CloseSend()

	// Get a file handle for the file we want to upload
	file, err = os.Open(appPkg)
	if err != nil {
		log.Error("failed to open package file")
		return util.Failure, err
	}
	defer file.Close()

	//send metadata information
	req := &lcmservice.UploadPackageRequest{

		Data: &lcmservice.UploadPackageRequest_AccessToken{
			AccessToken: accessToken,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Error(util.FailedToSendMetadataInfo)
		return util.Failure, err
	}

	//send metadata information
	req = &lcmservice.UploadPackageRequest{

		Data: &lcmservice.UploadPackageRequest_AppPackageId{
			AppPackageId: packageId,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Error(util.FailedToSendMetadataInfo)
		return util.Failure, err
	}

	//send metadata information
	req = &lcmservice.UploadPackageRequest{

		Data: &lcmservice.UploadPackageRequest_HostIp{
			HostIp: hostIP,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Error(util.FailedToSendMetadataInfo)
		return util.Failure, err
	}

	//send metadata information
	req = &lcmservice.UploadPackageRequest{

		Data: &lcmservice.UploadPackageRequest_TenantId{
			TenantId: tenantId,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Error(util.FailedToSendMetadataInfo)
		return util.Failure, err
	}

	// Allocate a buffer with `chunkSize` as the capacity
	// and length (making a 0 array of the size of `chunkSize`)
	buf = make([]byte, c.chunkSize)
	for writing {
		// put as many bytes as `chunkSize` into the
		// buf array.
		n, err = file.Read(buf)
		if err != nil {
			// ... if `eof` --> `writing=false`...
			if err == io.EOF {
				writing = false
				continue
			}
			log.Error("failed while copying from file to buf")
			return util.Failure, err
		}

		req := &lcmservice.UploadPackageRequest{
			Data: &lcmservice.UploadPackageRequest_Package{
				Package: buf[:n],
			},
		}

		err = stream.Send(req)

		if err != nil {
			log.Error("failed to send chunk via stream")
			return util.Failure, err
		}
	}

	res, err := stream.CloseAndRecv()
	if err != nil {
		log.Error("received upstream status response")
		return util.Failure, err
	}
	return res.GetStatus(), err
}

// Remove configuration
func (c *ClientGRPC) DeletePackage(ctx context.Context, tenantId string, hostIP string, packageId string, accessToken string) (status string, error error) {
	req := &lcmservice.DeletePackageRequest{
		HostIp:       hostIP,
		TenantId:     tenantId,
		AppPackageId: packageId,
		AccessToken:  accessToken,
	}

	log.WithFields(log.Fields{
		"tenant":     tenantId,
		"hostIp":     hostIP,
		"packageId":  packageId,
	}).Info("Delete Package!")

	resp, err := c.client.DeletePackage(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}
