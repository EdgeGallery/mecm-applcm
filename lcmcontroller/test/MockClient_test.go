package test

import (
	"context"
	"mime/multipart"
)

const SUCCESS_RETURN = "Success"

type MockClient struct{}

func (mc *MockClient) Instantiate(ctx context.Context, deployArtifact string, hostIP string,
	accessToken string, appInsId string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *MockClient) Terminate(ctx context.Context, hostIP string, accessToken string,
	appInsId string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *MockClient) Query(ctx context.Context, accessToken string, appInsId string,
	hostIP string) (response string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *MockClient) UploadConfig(ctx context.Context, multipartFile multipart.File,
	hostIP string, accessToken string) (status string, error error) {
	return SUCCESS_RETURN, nil
}

func (mc *MockClient) RemoveConfig(ctx context.Context, hostIP string,
	accessToken string) (status string, error error) {
	return SUCCESS_RETURN, nil
}
