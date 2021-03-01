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
	"k8splugin/internal/lcmservice"
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
type mockGrpcClient struct {
	conn      *grpc.ClientConn
	client    lcmservice.AppLCMClient
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
	c.client = lcmservice.NewAppLCMClient(conn)
	c.chunkSize = size
}

// Instantiate application
func (c *mockGrpcClient) Instantiate(deployArtifact string, hostIP string, accessToken string,
	appInsId string, ak string, sk string) (status string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	// Get a file handle for the file we want to upload
	file, _ := os.Open(deployArtifact)
	defer file.Close()

	// Open a stream-based connection with the gRPC server
	stream, _ := c.client.Instantiate(ctx)
	defer stream.CloseSend()

	//send metadata information
	req := &lcmservice.InstantiateRequest{
		Data: &lcmservice.InstantiateRequest_AccessToken{
			AccessToken: accessToken,
		},
	}
	_ = stream.Send(req)

	req = &lcmservice.InstantiateRequest{
		Data: &lcmservice.InstantiateRequest_Ak{
			Ak: ak,
		},
	}
	_ = stream.Send(req)

	req = &lcmservice.InstantiateRequest{
		Data: &lcmservice.InstantiateRequest_Sk{
			Sk: sk,
		},
	}
	_ = stream.Send(req)

	req = &lcmservice.InstantiateRequest{
		Data: &lcmservice.InstantiateRequest_AppInstanceId{
			AppInstanceId: appInsId,
		},
	}
	_ = stream.Send(req)

	//send metadata information
	req = &lcmservice.InstantiateRequest{
		Data: &lcmservice.InstantiateRequest_HostIp{
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
		req := &lcmservice.InstantiateRequest{
			Data: &lcmservice.InstantiateRequest_Package{
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

// Query application
func (c *mockGrpcClient) Query(accessToken string, appInsId string, hostIP string) (response string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	req := &lcmservice.QueryRequest{
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		HostIp:        hostIP,
	}
	resp, err := c.client.Query(ctx, req)
	return resp.Response, err
}

// Get workload description
func (c *mockGrpcClient) WorkloadDescribe(accessToken string, appInsId string, hostIP string) (response string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	req := &lcmservice.WorkloadDescribeRequest{
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
		HostIp:        hostIP,
	}
	resp, err := c.client.WorkloadDescribe(ctx, req)
	return resp.Response, err
}

// Terminate application
func (c *mockGrpcClient) Terminate(hostIP string, accessToken string, appInsId string) (status string, error error) {

	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()

	req := &lcmservice.TerminateRequest{
		HostIp:        hostIP,
		AccessToken:   accessToken,
		AppInstanceId: appInsId,
	}
	resp, err := c.client.Terminate(ctx, req)
	return resp.Status, err
}

// Remove configuration
func (c *mockGrpcClient) RemoveConfig(hostIP string, accessToken string) (status string, error error) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout*time.Second)
	defer cancel()
	req := &lcmservice.RemoveCfgRequest{
		HostIp:      hostIP,
		AccessToken: accessToken,
	}
	resp, err := c.client.RemoveConfig(ctx, req)
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
	req := &lcmservice.UploadCfgRequest{
		Data: &lcmservice.UploadCfgRequest_AccessToken{
			AccessToken: accessToken,
		},
	}
	_ = stream.Send(req)
	req = &lcmservice.UploadCfgRequest{
		Data: &lcmservice.UploadCfgRequest_HostIp{
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
