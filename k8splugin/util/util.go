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
	"errors"
	"k8splugin/conf"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	jwtPublicKey = os.Getenv("JWT_PUBLIC_KEY")
)

const (
	minPasswordSize = 8
	maxPasswordSize = 16
	specialCharRegex string = `['~!@#$%^&()-_=+\|[{}\];:'",<.>/?]`
	singleDigitRegex string = `\d`
	lowerCaseRegex string = `[a-z]`
	upperCaseRegex string = `[A-Z]`
	maxPasswordCount = 2
	Default string = "default"
	DriverName string = "postgres"
	InvalidToken string = "invalid token"
	CannotReceivePackage = "Cannot receive package metadata."
	FilePerm = 0750
	HostIpIsInvalid = "hostIp is invalid"
	TenantIdIsInvalid = "tenantId is invalid"
	AKIsInvalid = "ak is invalid"
	SKIsInvalid = "sk is invalid"
	PackageIdIsInvalid = "packageId is invalid"
	TenantIsInvalid = "hostIp is invalid"
	AccssTokenIsInvalid = "accessToken is invalid"
	Success = "Success"
	Failure = "Failure"
	ActionConfig = "Unable to initialize action config"
	HelmDriver = ""
	DeployType = "helm"
	AppInsId = "app_ins_id"
	AppPkgId = "app_pkg_id"
	maxHostNameLen = 253
	maxAkLen = 20
	maxSkLen = 64
	MaxIPVal = 255
	ServerNameRegex string = `^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`
	Forbidden string = "forbidden"
	MaxConfigFile              = 5242880
	MaxPackageFile             = 536870912

	FailedToDispRecvMsg    = "failed to display receive msg"
	FailedToValInputParams = "failed to validate input parameters"
	FailedToGetClient      = "failed to get client"
	AppRecordDoesNotExit   = "app info record does not exist in database"
	AppPkgRecordDoesNotExit   = "app package record does not exist in database"
	WorkloadEvents       = "WorkloadEvents"
	Query                  = "Query"
	QueryKPI               = "QueryKPI"
	Instantiate            = "Instantiate"
	Terminate              = "Terminate"
	UploadConfig           = "UploadConfig"
	UploadPackage          = "UploadPackage"
	RemoveConfig           = "RemoveConfig"
	DeletePackage          = "DeletePackage"
	UploadPackageStatus    = "UploadPackageStatus"
	MecmTenantRole         = "ROLE_MECM_TENANT"
	MecmAdminRole          = "ROLE_MECM_ADMIN"
	MecmGuestRole          = "ROLE_MECM_GUEST"

	TooManyFile int = 1024
	TooBig = 0x6400000
	SingleFileTooBig = 0x6400000
	RpcName = " RpcName ["
	Pod = "Pod"
	Deployment = "Deployment"
	Service = "Service"
	FailedToJsonMarshal = "Failed to json marshal"
	AppInsIdValid = "appInsId is invalid"
	FailedToDelAppPkg = "failed to delete application package"
	MaxSize = 20
	MaxBackups = 50
	MaxAge = 30
	Compress = true
	KubeConfigNotFound = "kubeconfig corresponding to given edge can't be found"
)

var cipherSuiteMap = map[string]uint16{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
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
	if pwdIsValid && err == nil {
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
func ValidateDbParams(dbPwd string) (bool, error) {
	dbPwdBytes := []byte(dbPwd)
	dbPwdIsValid, validateDbPwdErr := ValidatePassword(&dbPwdBytes)
	if validateDbPwdErr != nil || !dbPwdIsValid {
		return dbPwdIsValid, validateDbPwdErr
	}
	return true, nil
}

// Clear byte array from memory
func ClearByteArray(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}

// Validate access token
func ValidateAccessToken(accessToken string, allowedRoles []string) error {
	if accessToken == "" {
		return nil
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (interface{}, error) {
		return jwtPublicKey, nil
	})

	if token != nil && !token.Valid {
		err := validateTokenClaims(claims, allowedRoles)
		if err != nil {
			return err
		}
	} else if er, ok := err.(*jwt.ValidationError); ok {
		if er.Errors&jwt.ValidationErrorMalformed != 0 {
			log.Error("Invalid token")
			return errors.New(InvalidToken)
		} else if er.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			log.Error("token expired or inactive")
			return errors.New("token expired or inactive")
		} else {
			log.Error("Couldn't handle this token: ", err)
			return errors.New(err.Error())
		}
	} else {
		log.Error("Couldn't handle this token: ", err)
		return errors.New(err.Error())
	}

	log.Debug("Token validated successfully")
	return nil
}

// Validate token claims
func validateTokenClaims(claims jwt.MapClaims, allowedRoles []string) error {
	if claims["authorities"] == nil {
		log.Info("Invalid token A")
		return errors.New(InvalidToken)
	}

	err := ValidateRole(claims, allowedRoles)
	if err != nil {
		return err
	}

	if claims["userId"] == nil {
		log.Info("Invalid token UI")
		return errors.New(InvalidToken)
	}
	if claims["user_name"] == nil {
		log.Info("Invalid token UN")
		return errors.New(InvalidToken)
	}
	err = claims.Valid()
	if err != nil {
		log.Info("token expired")
		return errors.New(InvalidToken)
	}
	return nil
}

func ValidateRole(claims  jwt.MapClaims, allowedRoles []string) error {
	roleName := "defaultRole"
	log.Info(roleName)

	for key, value := range claims {
		if key == "authorities" {
			authorities := value.([]interface{})
			arr := reflect.ValueOf(authorities)
			for i := 0; i < arr.Len(); i++ {
				if arr.Index(i).Interface() == MecmTenantRole {
					roleName = MecmTenantRole
					break
				} else if arr.Index(i).Interface() == MecmGuestRole {
					roleName = MecmGuestRole
					break
				} else if arr.Index(i).Interface() == MecmAdminRole {
					roleName = MecmAdminRole
					break
				}
			}
			err := isValidUser(roleName,allowedRoles)
			if err != nil {
				log.Info("not authorised user")
				return err
			}
		}
	}
	return  nil
}

func isValidUser(roleName string, allowedRoles []string) error {
	if !isRoleAllowed(roleName, allowedRoles) {
		log.Info("Invalid token Authorities")
		if roleName == MecmGuestRole {
			return errors.New(Forbidden)
		}
		return errors.New(InvalidToken)
	}
	return nil
}

func isRoleAllowed(actual string, allowed []string) bool {
	for _, v := range allowed {
		if v == actual {
			return true
		}
	}
	return false
}

// Validate UUID
func ValidateUUID(id string) error {
	if id == "" {
		return errors.New("invalid uuid, uuid is empty")
	}

	if len(id) != 0 {
		validate := validator.New()
		res := validate.Var(id, "required,uuid")
		if res != nil {
			return errors.New("UUID validate failed")
		}
	}

	return nil
}

// Validate IPv4 address
func ValidateIpv4Address(ipAddress string) error {
	if ipAddress == "" {
		return errors.New("require ipAddress")
	}
	validate := validator.New()
	return validate.Var(ipAddress, "required,ipv4")
}

// Create directory
func CreateDir(path string) bool {
	_, err := os.Stat(path)

	if os.IsNotExist(err) {
		errDir := os.MkdirAll(path, FilePerm)
		if errDir != nil {
			return false
		}
	}
	return true
}

// Update tls configuration
func GetTLSConfig(config *conf.ServerConfigurations, certificate string, key string) (*tls.Config, error) {

	// Load the certificates from disk
	loadedCert, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		return nil, errors.New("could not load server key pair")
	}

	// Get valid server name
	serverName := config.ServerName
	serverNameIsValid, validateServerNameErr := ValidateServerName(serverName)
	if validateServerNameErr != nil || !serverNameIsValid {
		log.Error("validate server name error")
		return nil, validateServerNameErr
	}
	sslCiphers := config.SslCiphers
	if len(sslCiphers) == 0 {
		return nil, errors.New("TLS cipher configuration is not recommended or invalid")
	}
	cipherSuites := getCipherSuites(sslCiphers)
	if cipherSuites == nil {
		return nil, errors.New("TLS cipher configuration is not recommended or invalid")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{loadedCert},
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: cipherSuites,
	}, nil
}

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

// Validate Server Name
func ValidateServerName(serverName string) (bool, error) {
	if len(serverName) > maxHostNameLen {
		return false, errors.New("server or host name validation failed")
	}
	return regexp.MatchString(ServerNameRegex, serverName)
}

// Get configuration
func GetConfiguration(configPath string) (config *conf.Configurations, err error) {

	// Set the file name of the configurations file
	viper.SetConfigName("config")

	// Set the path to look for the configurations file
	viper.AddConfigPath(configPath)

	viper.SetConfigType("yaml")
	var configuration conf.Configurations

	if err = viper.ReadInConfig(); err != nil {
		log.Error("failed to read configuration file")
		return nil, err
	}

	err = viper.Unmarshal(&configuration)
	if err != nil {
		log.Errorf("Unable to decode into struct, %v", err)
		return nil, err
	}

	return &configuration, nil
}

// Get db user
func GetDbUser() string {
	dbUser := os.Getenv("K8S_PLUGIN_USER")
	return dbUser
}

// Get database name
func GetDbName() string {
	dbName := os.Getenv("K8S_PLUGIN_DB")
	return dbName
}

// Get database host
func GetDbHost() string {
	dbHost := os.Getenv("K8S_PLUGIN_DB_HOST")
	return dbHost
}

// Get database port
func GetDbPort() string {
	dbPort := os.Getenv("K8S_PLUGIN_DB_PORT")
	return dbPort
}

// Get release namespace
func GetReleaseNamespace() string {
	releaseNamespace := os.Getenv("RELEASE_NAMESPACE")
	return releaseNamespace
}

// Validate ak
func ValidateAk(ak string) error {
	if len(ak) > maxAkLen {
		return errors.New("ak validation failed")
	}
	return nil
}

// Validate sk
func ValidateSk(sk string) error {
	if len(sk) > maxSkLen {
		return errors.New("sk validation failed")
	}
	return nil
}

// get random secret name
func RandomSecretName(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}
