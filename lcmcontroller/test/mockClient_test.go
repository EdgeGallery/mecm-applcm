package test

import (
	"context"
	"mime/multipart"
)

const SUCCESS_RETURN = "Success"

type mockClient struct{}

func (mc *mockClient) Instantiate(ctx context.Context, deployArtifact string, hostIP string,
	accessToken string, appInsId string) (status string, error error) {
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
