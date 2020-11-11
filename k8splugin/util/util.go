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
	"archive/tar"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ghodss/yaml"
	"io"
	"io/ioutil"
	"k8splugin/conf"
	"os"
	"path/filepath"
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

const DB_REGEX string = `^[\w-]{4,16}$`
const DB_USER_REGEX = DB_REGEX
const DB_NAME_REGEX = DB_REGEX
const NAMESPACE_REGEX = DB_REGEX
const HOST_REGEX string = `^[\w-.]{4,16}$`
const PORT_REGEX string = `^([1-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$`
const minPasswordSize = 8
const maxPasswordSize = 16
const specialCharRegex string = `['~!@#$%^&()-_=+\|[{}\];:'",<.>/?]`
const singleDigitRegex string = `\d`
const lowerCaseRegex string = `[a-z]`
const upperCaseRegex string = `[A-Z]`
const maxPasswordCount = 2
const Default string = "default"
const DriverName string = "postgres"
const InvalidToken string = "invalid token"
const CannotReceivePackage = "Cannot receive package metadata."
const FilePerm = 0750
const TempFile = "temp.tar.gz"
const HostIpIsInvalid = "hostIp is invalid"
const AccssTokenIsInvalid = "accessToken is invalid"
const Success = "Success"
const Failure = "Failure"
const ActionConfig = "Unable to initialize action config"
const InvalidNamespace = "Invalid namespace"
const HelmDriver = ""
const DeployType = "helm"
const AppInsId = "app_ins_id"
const maxHostNameLen = 253
const maxAkLen = 20
const maxSkLen = 40
const ServerNameRegex string = `^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`

const FailedToDispRecvMsg    = "failed to display receive msg"
const FailedToValInputParams = "failed to validate input parameters"
const FailedToGetClient      = "failed to get client"
const AppRecordDoesNotExit   = "app info record does not exist in database\""
const Query        = "Query"
const Instantiate  = "Instantiate"
const Terminate    = "Terminate"
const UploadConfig = "UploadConfig"
const RemoveConfig = "RemoveConfig"

// Default environment variables
const dbuser    = "k8splugin"
const dbname    = "k8splugindb"
const dbhost    = "mepm-postgres"
const dbport    = "5432"
const namespace = "default"

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
func ValidateDbParams(dbUser string, dbPwd string, dbName string, dbHost string, dbPort string) (bool, error) {
	dbUserIsValid, validateDbUserErr := regexp.MatchString(DB_USER_REGEX, dbUser)
	if validateDbUserErr != nil || !dbUserIsValid {
		return dbUserIsValid, validateDbUserErr
	}
	dbPwdBytes := []byte(dbPwd)
	dbPwdIsValid, validateDbPwdErr := ValidatePassword(&dbPwdBytes)
	if validateDbPwdErr != nil || !dbPwdIsValid {
		return dbPwdIsValid, validateDbPwdErr
	}
	dbNameIsValid, validateDbNameErr := regexp.MatchString(DB_NAME_REGEX, dbName)
	if validateDbNameErr != nil || !dbNameIsValid {
		return dbNameIsValid, validateDbNameErr
	}
	dbHostIsValid, validateDbHostErr := regexp.MatchString(HOST_REGEX, dbHost)
	if validateDbHostErr != nil || !dbHostIsValid {
		return dbHostIsValid, validateDbHostErr
	}
	dbPortIsValid, validateDbPortErr := regexp.MatchString(PORT_REGEX, dbPort)
	if validateDbPortErr != nil || !dbPortIsValid {
		return dbPortIsValid, validateDbPortErr
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
func ValidateAccessToken(accessToken string) error {
	if accessToken == "" {
		return errors.New("require token")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (interface{}, error) {
		return jwtPublicKey, nil
	})

	if token != nil && !token.Valid {
		err := validateTokenClaims(claims)
		if err != nil {
			return err
		}
	} else if er, ok := err.(*jwt.ValidationError); ok {
		if er.Errors&jwt.ValidationErrorMalformed != 0 {
			log.Info("Invalid token")
			return errors.New(InvalidToken)
		} else if er.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			log.Infof("token expired or inactive")
			return errors.New("token expired or inactive")
		} else {
			log.Info("Couldn't handle this token: ", err)
			return errors.New(err.Error())
		}
	} else {
		log.Info("Couldn't handle this token: ", err)
		return errors.New(err.Error())
	}

	log.Info("Token validated successfully")
	return nil
}

// Validate token claims
func validateTokenClaims(claims jwt.MapClaims) error {
	if claims["authorities"] == nil {
		log.Info("Invalid token A")
		return errors.New(InvalidToken)
	}
	if claims["userId"] == nil {
		log.Info("Invalid token UI")
		return errors.New(InvalidToken)
	}
	if claims["user_name"] == nil {
		log.Info("Invalid token UN")
		return errors.New(InvalidToken)
	}
	err := claims.Valid()
	if err != nil {
		log.Info("token expired")
		return errors.New(InvalidToken)
	}
	return nil
}

// Validate UUID
func ValidateUUID(id string) error {
	if id == "" {
		return errors.New("require id")
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
func ValidateIpv4Address(ipAddress string) error {
	if ipAddress == "" {
		return errors.New("require ipAddress")
	}
	if len(ipAddress) != 0 {
		validate := validator.New()
		return validate.Var(ipAddress, "required,ipv4")
	}
	return nil
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
		return nil, fmt.Errorf("could not load server key pair: %s", err)
	}

	// Get valid server name
	serverName := config.Servername
	serverNameIsValid, validateServerNameErr := ValidateServerName(serverName)
	if validateServerNameErr != nil || !serverNameIsValid {
		log.Error("validate server name error")
		return nil, validateServerNameErr
	}
	sslCiphers := config.Sslciphers
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
	if dbUser == "" {
		dbUser = dbuser
	}
	return dbUser
}

// Get database name
func GetDbName() string {
	dbName := os.Getenv("K8S_PLUGIN_DB")
	if dbName == "" {
		dbName = dbname
	}
	return dbName
}

// Get database host
func GetDbHost() string {
	dbHost := os.Getenv("K8S_PLUGIN_DB_HOST")
	if dbHost == "" {
		dbHost = dbhost
	}
	return dbHost
}

// Get database port
func GetDbPort() string {
	dbPort := os.Getenv("K8S_PLUGIN_DB_PORT")
	if dbPort == "" {
		dbPort = dbport
	}
	return dbPort
}

// Get release namespace
func GetReleaseNamespace() string {
	releaseNamespace := os.Getenv("RELEASE_NAMESPACE")
	if releaseNamespace == "" {
		releaseNamespace = namespace
	}
	return releaseNamespace
}

// Validate namespace
func ValidateNameSpace(nameSpace string) (bool, error) {
	nameSpaceIsValid, validateNameSpaceErr := regexp.MatchString(NAMESPACE_REGEX, nameSpace)
	if validateNameSpaceErr != nil || !nameSpaceIsValid {
		return nameSpaceIsValid, validateNameSpaceErr
	}
	return true, nil
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

// extract the tar.gz file
func ExtractTarFile(gzipStream io.Reader) (string, error) {

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
func UpdateValuesFile(configPath, appInsId, ak, sk string) error {
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
	appConfig1["appnamespace"] = Default
	akskInfo := appConfig1["aksk"]
	akskConfig := akskInfo.(map[string]interface{})
	akskConfig["appInsId"] = appInsId
	akskConfig["accesskey"] = ak
	akskConfig["secretkey"] = sk
	akskConfig["secretname"] = appInsId
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
func CreateTarFile(source, target string) error {
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
