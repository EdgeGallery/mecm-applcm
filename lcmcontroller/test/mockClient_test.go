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
	"bytes"
	"context"
	"lcmcontroller/config"
	"mime/multipart"
)

const SUCCESS_RETURN = "Success"

type mockClient struct{}

func (mc *mockClient) CreateVmImage(ctx context.Context, accessToken string, appInsId string,
	hostIP string, vmId string) (response string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) QueryVmImage(ctx context.Context, accessToken string, appInsId string,
	hostIP string, imageId string) (response string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) DeleteVmImage(ctx context.Context, accessToken string, appInsId string,
	hostIP string, imageId string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) DownloadVmImage(ctx context.Context, accessToken string, appInsId string,
	hostIP string, imageId string, chunkNum int32) (response bytes.Buffer, error error) {
	return bytes.Buffer{}, nil
}

func (mc *mockClient) Instantiate(ctx context.Context, deployArtifact string, hostIP string,
	accessToken string, akSkAppInfo config.AppAuthConfig) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) Terminate(ctx context.Context, hostIP string, accessToken string,
	appInsId string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) Query(ctx context.Context, accessToken string, appInsId string,
	hostIP string) (response string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) UploadConfig(ctx context.Context, multipartFile multipart.File,
	hostIP string, accessToken string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) RemoveConfig(ctx context.Context, hostIP string,
	accessToken string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) WorkloadDescription(ctx context.Context, accessToken string, hostIp string,
	workloadName string) (response string, error error) {
	return SUCCESS_RETURN, nil
}
