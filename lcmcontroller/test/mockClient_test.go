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
	"lcmcontroller/models"
	"mime/multipart"
)

const SUCCESS_RETURN = "Success"

type mockClient struct{}

func (mc *mockClient) Instantiate(ctx context.Context, tenantId string, accessToken string, appInsId string, req models.InstantiateRequest) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) Terminate(ctx context.Context, hostIP string, tenantId string, accessToken string,
	appInsId string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) Query(ctx context.Context, accessToken string, appInsId string, hostIP string, tenantId string) (
	response string, error error) {
	return SUCCESS_RETURN, nil
}


func (mc *mockClient) QueryKPI(ctx context.Context, accessToken string, tenantId string, hostIP string) (response string,
	error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) UploadConfig(ctx context.Context, tenantId string,multipartFile multipart.File,
	hostIP string, accessToken string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) RemoveConfig(ctx context.Context, hostIP string, tenantId string,
	accessToken string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) WorkloadDescription(ctx context.Context, accessToken string, hostIp string,
	workloadName string, tenantId string) (response string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) UploadPackage(ctx context.Context, tenantId string, appPkg string, hostIP string,
	packageId string, accessToken string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) QueryPackageStatus(ctx context.Context, tenantId string, hostIP string,
	packageId string, accessToken string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *mockClient) DeletePackage(ctx context.Context, tenantId string, hostIP string, accessToken string,  packageId string) (status string, error error) {
	return SUCCESS_RETURN, nil
}




