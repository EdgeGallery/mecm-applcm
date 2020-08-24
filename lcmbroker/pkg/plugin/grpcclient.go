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

package plugin

import (
	"io"
	"lcmbroker/internal/lcmservice"
	"lcmbroker/util"
	"mime/multipart"
	"os"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip"
)

// GRPC client to different GRPC supported plugins
type ClientGRPC struct {
	conn      *grpc.ClientConn
	client    lcmservice.AppLCMClient
	chunkSize int
}

type ClientGRPCConfig struct {
	Address         string
	ChunkSize       int
	RootCertificate string
}

// Create a GRPC client
func NewClientGRPC(cfg ClientGRPCConfig) (c ClientGRPC, err error) {

	var (
		grpcOpts  []grpc.DialOption
		grpcCreds credentials.TransportCredentials
	)

	c.chunkSize = cfg.ChunkSize

	if cfg.RootCertificate != "" {
		grpcCreds, err = credentials.NewClientTLSFromFile(cfg.RootCertificate, "localhost")
		if err != nil {
			log.Errorf("failed to create grpc tls client via provided root-cert: %v", err)
			return c, err
		}
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(grpcCreds))
	} else {
		grpcOpts = append(grpcOpts, grpc.WithInsecure())
	}

	c.conn, err = grpc.Dial(cfg.Address, grpcOpts...)
	if err != nil {
		log.Errorf("failed to start grpc connection with address: %s", cfg.Address)
		return c, err
	}

	c.client = lcmservice.NewAppLCMClient(c.conn)
	return c, nil
}

// Instantiate application
func (c *ClientGRPC) Instantiate(ctx context.Context, deployArtifact string, hostIP string,
	accessToken string, appInsId string) (status string, error error) {
	var (
		writing = true
		buf     []byte
		n       int
		file    *os.File
	)

	// Get a file handle for the file we want to upload
	file, err := os.Open(deployArtifact)
	if err != nil {
		log.Errorf("failed to open package file: %s. Err: %s", deployArtifact, err.Error())
		return util.Failure, err
	}
	defer file.Close()

	// Open a stream-based connection with the
	// gRPC server
	stream, err := c.client.Instantiate(ctx)

	if err != nil {
		log.Errorf("failed to upload stream: %s. Err: %s", deployArtifact, err.Error())
		return util.Failure, err
	}
	defer stream.CloseSend()

	//send metadata information
	 req := &lcmservice.InstantiateRequest{

		Data: &lcmservice.InstantiateRequest_AccessToken{
			AccessToken: accessToken,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Errorf(util.FailedToSendMetadataInfo, err)
		return util.Failure, err
	}

	//send metadata information
	req = &lcmservice.InstantiateRequest{

		Data: &lcmservice.InstantiateRequest_AppInstanceId{
			AppInstanceId: appInsId,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Errorf(util.FailedToSendMetadataInfo, err)
		return util.Failure, err
	}

	//send metadata information
	req = &lcmservice.InstantiateRequest{

		Data: &lcmservice.InstantiateRequest_HostIp{
			HostIp: hostIP,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Errorf(util.FailedToSendMetadataInfo, err)
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
				err = nil
				continue
			}
			log.Errorf("errored while copying from file to buf: %v", err)
			return util.Failure, err
		}

		req := &lcmservice.InstantiateRequest{
			Data: &lcmservice.InstantiateRequest_Package{
				Package: buf[:n],
			},
		}

		err = stream.Send(req)

		if err != nil {
			log.Errorf("failed to send chunk via stream: %v", err)
			return util.Failure, err
		}
	}

	res, err := stream.CloseAndRecv()
	if err != nil {
		log.Errorf("failed to receive upstream status response: %v", err)
		return util.Failure, err
	}
	return res.GetStatus(), err
}

// Query application
func (c *ClientGRPC) Query(ctx context.Context, hostIP string) (status string, error error) {

	req := &lcmservice.QueryRequest{
		HostIp:     hostIP,
	}
	resp, err := c.client.Query(ctx, req)
	if err != nil {
		return"", err
	}
	return resp.Response, err
}

// Terminate application
func (c *ClientGRPC) Terminate(ctx context.Context, hostIP string, accessToken string, appInsId string) (status string, error error) {

	req := &lcmservice.TerminateRequest{
		HostIp:     hostIP,
		AccessToken: accessToken,
		AppInstanceId: appInsId,
	}
	resp, err := c.client.Terminate(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Status, err
}

func (c *ClientGRPC) RemoveConfig(ctx context.Context, hostIP string, accessToken string) (status string, error error) {
	req := &lcmservice.RemoveCfgRequest{
		HostIp:     hostIP,
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
		log.Errorf("failed to upload stream Err: %v", err)
		return util.Failure, err
	}
	defer stream.CloseSend()

	//send metadata information
	req := &lcmservice.UploadCfgRequest{

		Data: &lcmservice.UploadCfgRequest_HostIp{
			HostIp: hostIP,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Errorf(util.FailedToSendMetadataInfo, err)
		return util.Failure, err
	}

	req = &lcmservice.UploadCfgRequest{

		Data: &lcmservice.UploadCfgRequest_AccessToken{
			AccessToken: accessToken,
		},
	}

	err = stream.Send(req)
	if err != nil {
		log.Errorf(util.FailedToSendMetadataInfo, err)
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
				err = nil
				continue
			}
			log.Errorf("errored while copying from file to buf: %v", err)
			return util.Failure, err
		}

		req := &lcmservice.UploadCfgRequest{
			Data: &lcmservice.UploadCfgRequest_ConfigFile{
				ConfigFile: buf[:n],
			},
		}

		err = stream.Send(req)

		if err != nil {
			log.Errorf("failed to send chunk via stream: %v", err)
			return util.Failure, err
		}
	}

	res, err := stream.CloseAndRecv()
	if err != nil {
		log.Errorf("failed to receive upstream status response: %v", err)
		return util.Failure, err
	}
	log.Info("Instantiation Completed with status: ", res.GetStatus())
	return res.GetStatus(), err
}


func (c *ClientGRPC) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
