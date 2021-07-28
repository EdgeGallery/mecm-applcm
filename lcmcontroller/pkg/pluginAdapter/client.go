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
	"lcmcontroller/models"
	"mime/multipart"

	"golang.org/x/net/context"
)

// GRPC client APIs
type ClientIntf interface {
	Instantiate(ctx context.Context, tenantId string, accessToken string, appInsId string,
		req models.InstantiateRequest) (status string, error error)
	Terminate(ctx context.Context, hostIP string, accessToken string, appInsId string) (status string, error error)
	Query(ctx context.Context, accessToken string, appInsId string, hostIP string) (response string, error error)
	QueryKPI(ctx context.Context, accessToken string, hostIP string) (response string, error error)
	UploadConfig(ctx context.Context, multipartFile multipart.File,
		hostIP string, accessToken string) (status string, error error)
	RemoveConfig(ctx context.Context, hostIP string, accessToken string) (status string, error error)
	WorkloadDescription(ctx context.Context, accessToken string, appInsId string, hostIP string) (response string,
		error error)

	// App package API
	UploadPackage(ctx context.Context, tenantId string, appPkg string, hostIP string,
		packageId string, accessToken string) (status string, error error)
	DeletePackage(ctx context.Context, tenantId string, hostIP string, accessToken string,  packageId string) (status string, error error)


	// Image related API
	CreateVmImage(ctx context.Context, accessToken string, appInsId string, hostIP string, vmId string) (response string,
		error error)
	QueryVmImage(ctx context.Context, accessToken string, appInsId string, hostIP string,
		imageId string) (response string, error error)
	DeleteVmImage(ctx context.Context, accessToken string, appInsId string, hostIP string,
		imageId string) (status string, error error)
	DownloadVmImage(ctx context.Context, accessToken string, appInsId string, hostIP string,
		imageId string, chunkNum int32) (buf *bytes.Buffer, error error)
}
