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
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
	"lcmcontroller/util"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Generate test IP, instead of hard coding them
var (
	ipAddFormatter = "%d.%d.%d.%d"
	fwdIp          = fmt.Sprintf(ipAddFormatter, rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal), rand.Intn(util.MaxIPVal),
		rand.Intn(util.MaxIPVal))
	noMoreData = "No more data"
)

// Creates a new file upload http request with optional extra params
func getHttpRequest(uri string, params map[string]string, paramName string, path string,
	requestType string, requestBody []byte) (req *http.Request, err error) {

	var (
		writer *multipart.Writer
	)

	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		body := &bytes.Buffer{}
		writer = multipart.NewWriter(body)
		part, err := writer.CreateFormFile(paramName, filepath.Base(path))
		if err != nil {
			return nil, err
		}
		_, _ = io.Copy(part, file)

		for key, val := range params {
			_ = writer.WriteField(key, val)
		}
		err = writer.Close()
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(requestType, uri, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", writer.FormDataContentType())
	} else {
		//body := requestBody
		//_ = multipart.NewWriter(body)
		req, err = http.NewRequest(requestType, uri, bytes.NewBuffer(requestBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
	}

	accessToken := createToken("e921ce54-82c8-4532-b5c6-8516cf75f7a6")
	// Add additional headers
	req.Header.Set("access_token", accessToken)
	req.Header.Set("hostIp", "1.1.1.1")
	req.Header.Set("appName", "testApplication")
	req.Header.Set("appId", "e261211d80d04cb6aed00e5cd1f2cd1")
	req.Header.Set("packageId", packageId)
	req.Header.Set("X-Forwarded-For", fwdIp)
	req.Header.Set("chunk_num", "0")

	// Parse and create multipart form
	_ = req.ParseMultipartForm(32 << 20)

	return req, err
}

func createToken(userid string) string {
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	roleName := make([]string, 4)
	roleName[1] = "ROLE_MECM_TENANT"
	roleName[2] = "ROLE_APPSTORE_TENANT"
	roleName[3] = "ROLE_DEVELOPER_TENANT"
	atClaims["authorities"] = roleName
	atClaims["user_name"] = "lcmcontroller"
	atClaims["authorized"] = true
	atClaims["userId"] = userid
	atClaims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, _ := at.SignedString([]byte("jdnfksdmfksd"))
	return token
}

func createTokenAdmin(userid string) string {
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	roleName := make([]string, 4)
	roleName[0] = "ROLE_MECM_ADMIN"
	roleName[2] = "ROLE_APPSTORE_TENANT"
	roleName[3] = "ROLE_DEVELOPER_TENANT"
	atClaims["authorities"] = roleName
	atClaims["user_name"] = "lcmcontroller"
	atClaims["authorized"] = true
	atClaims["userId"] = userid
	atClaims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, _ := at.SignedString([]byte("jdnfksdmfksd"))
	return token
}
