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

package config

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"k8splugin/util"
	"os"
	"path/filepath"
	"strings"
)

// Ak sk and appInsId info
type AppAuthConfig struct {
	AppInsId string
	Ak       string
	Sk       string
}

// Constructor to Application configuration
func NewAppConfigBuilder(appInsId string, ak string, sk string) (appAuthCfg AppAuthConfig) {
	appAuthCfg.AppInsId = appInsId
	appAuthCfg.Ak = ak
	appAuthCfg.Sk = sk
	return
}

// extract the tar.gz file
func (_ *AppAuthConfig) ExtractTarFile(gzipStream io.Reader) (string, error) {
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		log.Error("failed to read the file")
		return "", err
	}

	dirName, err := processTarFile(uncompressedStream)
	if err != nil {
		log.Error("failed to process the tar file")
		return "", err
	}

	return dirName, nil
}

// Process tar file
func processTarFile(uncompressedStream *gzip.Reader) (string, error) {
	var dirName []string
	var count = 0

	tarReader := tar.NewReader(uncompressedStream)
	for true {
		header, err := tarReader.Next()
		if err == io.EOF || header == nil {
			break
		}

		if header.Typeflag == tar.TypeDir {
			_ = os.MkdirAll(header.Name, 0755)
		} else if header.Typeflag == tar.TypeReg {
			dir, _ := filepath.Split(header.Name)
			if count == 0 {
				dirName = strings.Split(dir, "/")
				count += 1
			}
			err := handleRegularFile(dir, header, tarReader)
			if err != nil {
				return "", err
			}
		}
	}
	return dirName[0], nil
}

// Handle regular file
func handleRegularFile(dir string, header *tar.Header, tarReader *tar.Reader) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Error("failed to create the directory")
		return err
	}
	outFile, err := os.Create(header.Name)
	if err != nil {
		log.Error("failed to create the file")
		return err
	}
	defer outFile.Close()
	if _, err := io.Copy(outFile, tarReader); err != nil {
		log.Error("failed to copy the file")
		return err
	}
	return nil
}

// update values yaml file
func (appAuthCfg *AppAuthConfig) UpdateValuesFile(configPath string) error {
	values, err := ioutil.ReadFile(configPath + "/values.yaml")
	if err != nil {
		log.Error("Failed to read values yaml file")
		return err
	}

	jsondata, err := yaml.YAMLToJSON(values)
	if err != nil {
		log.Error("Failed to convert yaml to json")
		return err
	}

	var appAuthConfig map[string]interface{}
	err = json.Unmarshal(jsondata, &appAuthConfig)
	if err != nil {
		log.Error("Failed to unmarshal appAuthConfig")
		return err
	}
	appConfig := appAuthConfig["appconfig"]
	appConfig1 := appConfig.(map[string]interface{})
	appConfig1["appnamespace"] = util.Default
	akskInfo := appConfig1["aksk"]
	akskConfig := akskInfo.(map[string]interface{})
	akskConfig["appInsId"] = appAuthCfg.AppInsId
	akskConfig["accesskey"] = appAuthCfg.Ak
	akskConfig["secretkey"] = appAuthCfg.Sk
	akskConfig["secretname"] = appAuthCfg.AppInsId
	appAuthInfo, err := yaml.Marshal(&appAuthConfig)
	if err != nil {
		log.Error("Failed to marshal appAuthConfig")
		return err
	}

	err = ioutil.WriteFile(configPath + "/values.yaml", appAuthInfo, 0644)
	if err != nil {
		log.Error("Failed to update values yaml file")
		return err
	}

	return nil
}

// create a tar file
func (_ *AppAuthConfig) CreateTarFile(source, target string) error {
	filename := filepath.Base(source)

	target = filepath.Join(target, fmt.Sprintf("%s.tar.gz", filename))
	tarfile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer tarfile.Close()

	// set up the gzip writer
	gw := gzip.NewWriter(tarfile)
	defer gw.Close()

	tarball := tar.NewWriter(gw)
	defer tarball.Close()

	info, err := os.Stat(source)
	if err != nil {
		return nil
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}

	return filepath.Walk(source,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return err
			}

			if baseDir != "" {
				header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
			}


			if err := tarball.WriteHeader(header); err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(tarball, file)
			return err
		})
}
