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
	log "github.com/sirupsen/logrus"
	"io"
	"k8splugin/internal/internal_lcmservice"
	"k8splugin/util"
	"os"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
)

const (
	size    = 1024
	Timeout = 180
)

// mock GRPC client
type  mockGrpcClient struct {
	conn      *grpc.ClientConn
	client    internal_lcmservice.AppLCMClient
	chunkSize int
}

// Create a GRPC client
func (c *mockGrpcClient) dialToServer(address string) {
	var (
		grpcOpts []grpc.DialOption
	)
	grpcOpts = append(grpcOpts, grpc.WithInsecure())
	conn, err := grpc.Dial(address, grpcOpts...)
	if err != nil {
		log.Error("Error while dialing to server")
	}
	c.conn = conn
	c.client = internal_lcmservice.NewAppLCMClient(conn)
	c.chunkSize = size
}
// Upload Package
func (c *mockGrpcClient) UploadPkg(deployArtifact string, hostIP string,
	accessToken string, packageId string, tenantId string) (status string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	// Get a file handle for the file we want to upload
	file, _ := os.Open(deployArtifact)
	defer file.Close()

	// Open a stream-based connection with the gRPC server
	stream, _ := c.client.UploadPackage(ctx)
	defer stream.CloseSend()

	//send metadata information
	req := &internal_lcmservice.UploadPackageRequest{
		Data: &internal_lcmservice.UploadPackageRequest_AccessToken{
			AccessToken: accessToken,
		},
	}
	_ = stream.Send(req)
	req = &internal_lcmservice.UploadPackageRequest{
		Data: &internal_lcmservice.UploadPackageRequest_AppPackageId{
			AppPackageId: packageId,
		},
	}
	_ = stream.Send(req)
	req = &internal_lcmservice.UploadPackageRequest{
		Data: &internal_lcmservice.UploadPackageRequest_HostIp{
			HostIp: hostIP,
		},
	}
	_ = stream.Send(req)

	req = &internal_lcmservice.UploadPackageRequest{
		Data: &internal_lcmservice.UploadPackageRequest_TenantId{
			TenantId: tenantId,
		},
	}
	_ = stream.Send(req)

	// Allocate a buffer with `chunkSize` as the capacity
	// and length (making a 0 array of the size of `chunkSize`)
	buf := make([]byte, c.chunkSize)
	var writing = true
	for writing {
		// put as many bytes as `chunkSize` into the
		// buf array.
		n, err := file.Read(buf)
		if err != nil {
			// ... if `eof` --> `writing=false`...
			if err == io.EOF {
				writing = false
				continue
			}
			log.Error("failed while copying from file to buf")
			return util.Failure, err
		}
		req := &internal_lcmservice.UploadPackageRequest{
			Data: &internal_lcmservice.UploadPackageRequest_Package{
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
		log.Error("failed to receive upstream status response")
		return util.Failure, err
	}
	return res.GetStatus(), err
}


// Delete Package
func (c *mockGrpcClient) DeletePkg() (status string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	req := &internal_lcmservice.DeletePackageRequest{
		HostIp:        hostIpAddress,
		AccessToken:   token,
		AppPackageId:  packageId,
		TenantId:      tenantIdentifier,

	}
	resp, err := c.client.DeletePackage(ctx, req)
	if resp == nil {
		return "", err
	}
	req = &internal_lcmservice.DeletePackageRequest{
		HostIp:        "256.1.1.1",
		AccessToken:   token,
		AppPackageId:  packageId,
		TenantId:      tenantIdentifier,

	}
	_, err = c.client.DeletePackage(ctx, req)
	token1 := "1"
	req = &internal_lcmservice.DeletePackageRequest{
		HostIp:        hostIpAddress,
		AccessToken:   token1,
		AppPackageId:  packageId,
		TenantId:      tenantIdentifier,

	}
	_, err = c.client.DeletePackage(ctx, req)
	req = &internal_lcmservice.DeletePackageRequest{
		HostIp:        hostIpAddress,
		AccessToken:   token,
		AppPackageId:  "",
		TenantId:      tenantIdentifier,

	}
	_, err = c.client.DeletePackage(ctx, req)
	req = &internal_lcmservice.DeletePackageRequest{
		HostIp:        hostIpAddress,
		AccessToken:   token,
		AppPackageId:  packageId,
		TenantId:      "1",

	}
	_, err = c.client.DeletePackage(ctx, req)

	return resp.Status, err
}

// Instantiate application
func (c *mockGrpcClient) Instantiate(deployArtifact string, hostIP string, accessToken string,
	appInsId string, ak string, sk string) (status string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()
	parameters := make(map[string]string)
	parameters["ak"] = ak
	parameters["sk"] = sk
	req := &internal_lcmservice.InstantiateRequest{
		HostIp:        hostIP,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		AppPackageId:  packageId,
		TenantId:      tenantIdentifier,
		Parameters:    parameters,
	}
	resp, err := c.client.Instantiate(ctx, req)
	if resp == nil {
		return "", err
	}
	req = &internal_lcmservice.InstantiateRequest{
		HostIp:        hostIP,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		AppPackageId:  packageId,
		TenantId:      "1",
		Parameters:    parameters,
	}
	_, err = c.client.Instantiate(ctx, req)
	req = &internal_lcmservice.InstantiateRequest{
		HostIp:        hostIP,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		AppPackageId:  "",
		TenantId:      tenantIdentifier,
		Parameters:    parameters,
	}
	_, err = c.client.Instantiate(ctx, req)
	return resp.Status, err
}

// Query application
func (c *mockGrpcClient) Query(accessToken string, appInsId string, hostIP string) (response string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	req := &internal_lcmservice.QueryRequest{
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		HostIp:        hostIP,
		TenantId:      tenantId,
	}
	resp, err := c.client.Query(ctx, req)
	if resp == nil {
		return "", err
	}
	return resp.Response, err
}


// Query kpi application
func (c *mockGrpcClient) QueryKpiInfo(accessToken string, hostIP string) (response string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	req := &internal_lcmservice.QueryKPIRequest{
		AccessToken:   accessToken,
		HostIp:        hostIP,
		TenantId:      tenantId,
	}
	resp, err := c.client.QueryKPI(ctx, req)
	if resp == nil {
		return "", err
	}
	return resp.Response, err
}



// Get workload description
func (c *mockGrpcClient) WorkloadEvents(accessToken string, appInsId string, hostIP string) (response string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	req := &internal_lcmservice.WorkloadEventsRequest{
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		HostIp:        hostIP,
		TenantId:      tenantId,
	}
	resp, err := c.client.WorkloadEvents(ctx, req)
	if resp == nil {
		return "", err
	}
	return resp.Response, err
}

// Terminate application
func (c *mockGrpcClient) Terminate(hostIP string, accessToken string, appInsId string) (status string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	req := &internal_lcmservice.TerminateRequest{
		HostIp:        hostIP,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		TenantId:      tenantId,
	}
	resp, err := c.client.Terminate(ctx, req)
	if resp == nil {
		return "", err
	}
	return resp.Status, err
}

// Remove configuration
func (c *mockGrpcClient) RemoveConfig(hostIP string, accessToken string) (status string, error error) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()
	req := &internal_lcmservice.RemoveCfgRequest{
		HostIp:      hostIP,
		TenantId:    tenantId,
		AccessToken: accessToken,
	}
	resp, err := c.client.RemoveConfig(ctx, req)
	if resp == nil {
		return "", err
	}
	return resp.Status, err
}

// Upload Configuration
func (c *mockGrpcClient) UploadConfig(deployArtifact string, hostIP string,
	accessToken string) (status string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	// Get a file handle for the file we want to upload
	file, _ := os.Open(deployArtifact)
	defer file.Close()

	// Open a stream-based connection with the gRPC server
	stream, _ := c.client.UploadConfig(ctx)
	defer stream.CloseSend()

	//send metadata information
	req := &internal_lcmservice.UploadCfgRequest{
		Data: &internal_lcmservice.UploadCfgRequest_AccessToken{
			AccessToken: accessToken,
		},
	}
	_ = stream.Send(req)
	req = &internal_lcmservice.UploadCfgRequest{
		Data: &internal_lcmservice.UploadCfgRequest_TenantId{
			TenantId: tenantId,
		},
	}
	_ = stream.Send(req)

	req = &internal_lcmservice.UploadCfgRequest{
		Data: &internal_lcmservice.UploadCfgRequest_HostIp{
			HostIp: hostIP,
		},
	}
	_ = stream.Send(req)

	// Allocate a buffer with `chunkSize` as the capacity
	// and length (making a 0 array of the size of `chunkSize`)
	buf := make([]byte, c.chunkSize)
	var writing = true
	for writing {
		// put as many bytes as `chunkSize` into the
		// buf array.
		n, err := file.Read(buf)
		if err != nil {
			// ... if `eof` --> `writing=false`...
			if err == io.EOF {
				writing = false
				continue
			}
			log.Error("failed while copying from file to buf")
			return util.Failure, err
		}
		req := &internal_lcmservice.UploadCfgRequest{
			Data: &internal_lcmservice.UploadCfgRequest_ConfigFile{
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
		log.Error("failed to receive upstream status response")
		return util.Failure, err
	}
	return res.GetStatus(), err
}

// Close connection
func (c *mockGrpcClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
