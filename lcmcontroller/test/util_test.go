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
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

const (
	FWDIP          = "1.1.1.1:10000"
	HOST_IP_STRING = "hostIp"
)

// Creates a new file upload http request with optional extra params
func getHttpRequest(uri string, params map[string]string, paramName string, path string,
	requestType string) (req *http.Request, err error) {

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
		_, err = io.Copy(part, file)

		for key, val := range params {
			_ = writer.WriteField(key, val)
		}
		err = writer.Close()
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(requestType, uri, body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
	} else {
		body := &bytes.Buffer{}
		writer = multipart.NewWriter(body)
		req, err = http.NewRequest(requestType, uri, body)
		req.Header.Set("Content-Type", "application/json")
	}
	if err != nil {
		return nil, err
	}

	// Add additional headers
	req.Header.Set("access_token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiI3MjY5NjM4ZS01NjM3LTRiOGM"+
		"tODE3OC1iNTExMmJhN2I2OWIiLCJzY29wZSI6WyJhbGwiXSwiZXhwIjoxNTk5Mjc5NDA3LCJzc29TZXNzaW9uSWQiOiI1QkYwNjM2QzlBMkEzMUI2NEEwM"+
		"EFCRTk1OTVEN0E0NyIsInVzZXJOYW1lIjoid2Vuc29uIiwidXNlcklkIjoiNzI2OTYzOGUtNTYzNy00YjhjLTgxNzgtYjUxMTJiYTdiNjliIiwiYXV0aG9"+
		"yaXRpZXMiOlsiUk9MRV9BUFBTVE9SRV9URU5BTlQiLCJST0xFX0RFVkVMT1BFUl9URU5BTlQiLCJST0xFX01FQ01fVEVOQU5UIl0sImp0aSI6IjQ5ZTBhM"+
		"GMwLTIxZmItNDAwZC04M2MyLTI3NzIwNWQ1ZTY3MCIsImNsaWVudF9pZCI6Im1lY20tZmUiLCJlbmFibGVTbXMiOiJ0cnVlIn0.kmJbwyAxPj7OKpP-5r-"+
		"WMVKbETpKV0kWMguMNaiNt63EhgrmfDgjmX7eqfagMYBS1sgIKZjuxFg2o-HUaO4h9iE1cLkmm0-8qV7HUSkMQThXGtUk2xljB6K9RxxZzzQNQFpgBB7gE"+
		"cGVc_t_86tLxUU6FxXEW1h-zW4z4I_oGM9TOg7JR-ZyC8lQZTBNiYaOFHpvEubeqfQL0AFIKHeEf18Jm-Xjjw4Y3QEzB1qDMrOGh-55y8kelW1w_Vwbaz4"+
		"5n5-U0DirDpCaa4ergleQIVF6exdjMWKtANGYU6zy48u7EYPYsykkDoIOxWYNqWSe557rNvY_3m1Ynam1QJCYUA")
	req.Header.Set("X-Forwarded-For", FWDIP)

	// Parse and create multipart form
	_ = req.ParseMultipartForm(32 << 20)

	return req, err
}
