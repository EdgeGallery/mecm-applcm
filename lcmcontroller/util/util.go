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

package util

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/astaxie/beego"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
)

var (
	jwtPublicKey        = os.Getenv("JWT_PUBLIC_KEY")
)

const XRealIp string = "X-Real-Ip"
const AccessToken string = "access_token"
const HelmPlugin string = "helmplugin"
const HelmPluginPort string = "HELM_PLUGIN_PORT"
const AuthorizationFailed string = "Authorization failed"
const InstantiationFailed string = "Instantiation failed"
const Default string = "default"
const DriverName string = "postgres"
const Failure string = "Failure"
const ClientIpaddressInvalid = "cientIp address is invalid"
const FailedToSendMetadataInfo string = "failed to send metadata information"
const FailedToCreateClient string = "failed to create client: %v"
const DeployTypeIsNotHelmBased = "Deployment type is not helm based"
const InvalidToken string = "invalid token"
const MaxSize int = 20
const MaxBackups int = 50
const MaxAge = 30
const MaxConfigFile int64 = 5242880
const Timeout = 5

const BadRequest int = 400
const StatusUnauthorized int = 401
const StatusInternalServerError int = 500

const DbRegex string = `^[\w-]{4,16}$`
const DbUserRegex = DbRegex
const DbNameRegex = DbRegex
const HostRegex string = `^[\w-.]{4,16}$`
const PortRegex string = `^[0-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]$`

const minPasswordSize = 8
const maxPasswordSize = 16
const specialCharRegex string = `['~!@#$%^&()-_=+\|[{}\];:'",<.>/?]`
const singleDigitRegex string = `\d`
const lowerCaseRegex string = `[a-z]`
const upperCaseRegex string = `[A-Z]`
const maxPasswordCount = 2

const HttpUrl string = "http://"
const CpuQuery string = "/api/v1/query?query=sum(kube_pod_container_resource_requests_cpu_cores)" +
	                    "/sum(kube_node_status_allocatable_cpu_cores)"
const MemQuery string = "/api/v1/query?query=sum(kube_pod_container_resource_requests_memory_bytes)" +
	                    "/ sum(kube_node_status_allocatable_memory_bytes)"
const DiskQuery string = "/api/v1/query?query=(sum (node_filesystem_size_bytes)-" +
	                     "sum (node_filesystem_free_bytes)) / sum (node_filesystem_size_bytes)"

var cipherSuiteMap = map[string]uint16{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// Get app configuration
func GetAppConfig(k string) string {
	return beego.AppConfig.String(k)
}

// Validate UUID
func ValidateUUID(id string) error {
	if id == "" {
		return errors.New("require app instance id")
	}
	if len(id) != 0 {
		validate := validator.New()
		res := validate.Var(id, "required,uuid")
		if res != nil {
			return errors.New("UUID validate failed")
		}
	} else {
		return errors.New("UUID validate failed")
	}
	return nil
}

// Validate IPv4 address
func ValidateIpv4Address(id string) error {
	if id == "" {
		return errors.New("require ip address")
	}
	if len(id) != 0 {
		validate := validator.New()
		return validate.Var(id, "required,ipv4")
	}
	return nil
}

// Validate file size
func ValidateFileSize(fileSize int64, maxFileSize int64) error {
	if fileSize < maxFileSize {
		return nil
	}
	return errors.New("invalid file, file size is larger than max size")
}

// Clear byte array from memory
func ClearByteArray(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}

// Validate password
func ValidatePassword(password *[]byte) (bool, error) {
	if len(*password) >= minPasswordSize && len(*password) <= maxPasswordSize {
		// password must satisfy any two conditions
		pwdValidCount := getPasswordValidCount(password)
		if pwdValidCount < maxPasswordCount {
			return false, errors.New("password must contain at least two types of the either one lowercase" +
				" character, one uppercase character, one digit or one special character")
		}
	} else {
		return false, errors.New("password must have minimum length of 8 and maximum of 16")
	}
	return true, nil
}

// To get password valid count
func getPasswordValidCount(password *[]byte) int {
	var pwdValidCount = 0
	pwdIsValid, err := regexp.Match(singleDigitRegex, *password)
	if pwdIsValid && err == nil {
		pwdValidCount++
	}
	pwdIsValid, err = regexp.Match(lowerCaseRegex, *password)
	if pwdIsValid && err == nil {
		pwdValidCount++
	}
	pwdIsValid, err = regexp.Match(upperCaseRegex, *password)
	if pwdIsValid && err == nil  {
		pwdValidCount++
	}
	// space validation for password complexity is not added
	// as jwt decrypt fails if space is included in password
	pwdIsValid, err = regexp.Match(specialCharRegex, *password)
	if pwdIsValid && err == nil {
		pwdValidCount++
	}
	return pwdValidCount
}

// Validate db parameters
func ValidateDbParams(dbUser string, dbPwd string, dbName string, dbHost string, dbPort string) (bool, error) {
	dbUserIsValid, validateDbUserErr := regexp.MatchString(DbUserRegex, dbUser)
	if validateDbUserErr != nil || !dbUserIsValid {
		return dbUserIsValid, validateDbUserErr
	}
	dbPwdBytes := []byte(dbPwd)
	dbPwdIsValid, validateDbPwdErr := ValidatePassword(&dbPwdBytes)
	if validateDbPwdErr != nil || !dbPwdIsValid {
		return dbPwdIsValid, validateDbPwdErr
	}
	dbNameIsValid, validateDbNameErr := regexp.MatchString(DbNameRegex, dbName)
	if validateDbNameErr != nil || !dbNameIsValid {
		return dbNameIsValid, validateDbNameErr
	}
	dbHostIsValid, validateDbHostErr := regexp.MatchString(HostRegex, dbHost)
	if validateDbHostErr != nil || !dbHostIsValid {
		return dbHostIsValid, validateDbHostErr
	}
	dbPortIsValid, validateDbPortErr := regexp.MatchString(PortRegex, dbPort)
	if validateDbPortErr != nil || !dbPortIsValid {
		return dbPortIsValid, validateDbPortErr
	}
	return true, nil
}

// Validate access token
func ValidateAccessToken(accessToken string) error {
	if accessToken == "" {
		return errors.New("require token")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (interface{}, error) {
		return jwtPublicKey, nil
	})

	if token != nil && !token.Valid {
		if claims["authorities"] == nil {
			log.Info("Invalid token A")
			return  errors.New(InvalidToken)
		}
		if claims["userId"] == nil {
			log.Info("Invalid token UI")
			return  errors.New(InvalidToken)
		}
		if claims["user_name"] == nil {
			log.Info("Invalid token UN")
			return  errors.New(InvalidToken)
		}
	} else if er, ok := err.(*jwt.ValidationError); ok {
		if er.Errors&jwt.ValidationErrorMalformed != 0 {
			log.Info("Invalid token")
			return  errors.New(InvalidToken)
		} else if er.Errors&(jwt.ValidationErrorExpired | jwt.ValidationErrorNotValidYet) != 0 {
			log.Infof("token expired or inactive")
			return  errors.New("token expired or inactive")
		} else {
			log.Info("Couldn't handle this token: ", err)
			return  errors.New(err.Error())
		}
	} else {
		log.Info("Couldn't handle this token: ", err)
		return  errors.New(err.Error())
	}

	log.Info("Token validated successfully")
	return nil
}

// Update tls configuration
func TLSConfig(crtName string) (*tls.Config, error) {
	certNameConfig := GetAppConfig(crtName)
	if len(certNameConfig) == 0 {
		log.Error(crtName + " configuration is not set")
		return nil, errors.New("cert name configuration is not set")
	}

	crt, err := ioutil.ReadFile(certNameConfig)
	if err != nil {
		log.Error("unable to read certificate")
		return nil, err
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(crt)


	sslCiphers := GetAppConfig("ssl_ciphers")
	if len(sslCiphers) == 0 {
		return nil, errors.New("TLS cipher configuration is not recommended or invalid")
	}
	cipherSuites := getCipherSuites(sslCiphers)
	if cipherSuites == nil {
		return nil, errors.New("TLS cipher configuration is not recommended or invalid")
	}
	return &tls.Config{
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: cipherSuites,
	}, nil
}

// To get cipher suites
func getCipherSuites(sslCiphers string) []uint16 {
	cipherSuiteArr := make([]uint16, 0, 5)
	cipherSuiteNameList := strings.Split(sslCiphers, ",")
	for _, cipherName := range cipherSuiteNameList {
		cipherName = strings.TrimSpace(cipherName)
		if len(cipherName) == 0 {
			continue
		}
		mapValue, ok := cipherSuiteMap[cipherName]
		if !ok {
			log.Error("not recommended cipher suite")
			return nil
		}
		cipherSuiteArr = append(cipherSuiteArr, mapValue)
	}
	if len(cipherSuiteArr) > 0 {
		return cipherSuiteArr
	}
	return nil
}
