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
	"github.com/astaxie/beego/context"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
	"github.com/ulule/limiter/v3"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var (
	jwtPublicKey = os.Getenv("JWT_PUBLIC_KEY")
)

const AccessToken string = "access_token"
const K8sPlugin string = "K8S_PLUGIN"
const K8sPluginPort string = "K8S_PLUGIN_PORT"
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
const IllegalTenantId string = "Illegal TenantId"
const AppInsId = "app_ins_id"
const TenantId = "tenant_id"
const FailedToGetClient = "Failed to get client"
const FailedToGetPluginInfo = "Failed to get plugin info"
const PortIsNotValid = "port is not valid"
const MepCapabilityIsNotValid = "MEP capability id is not valid"
const MaxSize int = 20
const MaxBackups int = 50
const MaxAge = 30
const MaxConfigFile int64 = 5242880
const Timeout = 180
const NonManoArtifactSets = "non_mano_artifact_sets"
const MaxNumberOfRecords = 50
const MaxFileNameSize = 64

const BadRequest int = 400
const StatusUnauthorized int = 401
const StatusInternalServerError int = 500
const StatusNotFound int = 404

const DbRegex string = `^[\w-]{4,32}$`
const DbUserRegex = DbRegex
const DbNameRegex = DbRegex
const SericeNameRegex = DbRegex
const HostRegex string = `^[\w-.]{4,16}$`
const PortRegex string = `^[0-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]$`
const UuidRegex string = `^[a-fA-F0-9]{8}[a-fA-F0-9]{4}4[a-fA-F0-9]{3}[8|9|aA|bB][a-fA-F0-9]{3}[a-fA-F0-9]{12}$`
const AppNameRegex = DbRegex

const minPasswordSize = 8
const maxPasswordSize = 16
const specialCharRegex string = `['~!@#$%^&()-_=+\|[{}\];:'",<.>/?]`
const singleDigitRegex string = `\d`
const lowerCaseRegex string = `[a-z]`
const upperCaseRegex string = `[A-Z]`
const maxPasswordCount = 2
const maxMepCapabilityIdLen = 32

const TooManyFile int = 1024
const TooBig = 0x6400000
const SingleFileTooBig = 0x6400000

const HttpUrl string = "http://"
const HttpsUrl string = "https://"
const CpuQuery string = "/api/v1/query?query=sum(kube_pod_container_resource_requests_cpu_cores)/sum(kube_node_status_allocatable_cpu_cores)"
const MemQuery string = "/api/v1/query?query=sum(kube_pod_container_resource_requests_memory_bytes)/sum(kube_node_status_allocatable_memory_bytes)"
const DiskQuery string = "/api/v1/query?query=(sum(node_filesystem_size_bytes)-sum(node_filesystem_free_bytes))/sum(node_filesystem_size_bytes)"
const UnexpectedValue = "unexpected value found"
const MarshalError = "Failed to marshal json"
const UnMarshalError = "Failed to unmarshal json"
const FailedToWriteRes = "Failed to write response into context"
const BaseUriMec = "/mec/v1/mgmt/tenant/"
const CapabilityUri = "/mepcfg/mec_platform_config/v1/capabilities"
const ApiGwAddr = "API_GW_ADDR"
const ApiGwPort = "API_GW_PORT"
const apigwAddr = "edgegallery"
const apigwPort = "8444"
const MecmTenantRole = "ROLE_MECM_TENANT"
const MecmGuestRole = "ROLE_MECM_GUEST"
const UserId = "7f9cac8d-7c54-23e7-99c6-27e4d944d5de"
const MaxIPVal = 255
const IpAddFormatter = "%d.%d.%d.%d"
const PromethuesServerName = "mep-prometheus-server"

// Default environment variables
const dbuser = "lcmcontroller"
const dbname = "lcmcontrollerdb"
const dbhost = "mepm-postgres"
const dbport = "5432"
const prometheusport = "80"
const mepport = "80"
const k8splugin = "mecm-mepm-k8splugin"
const k8spluginport = "8095"

var cipherSuiteMap = map[string]uint16{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

type RateLimiter struct {
	GeneralLimiter *limiter.Limiter
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

func IsValidUUID(uuid string) (bool, error) {
	uuidIsValid, valUuidErr := regexp.MatchString(UuidRegex, uuid)
	if valUuidErr != nil || !uuidIsValid {
		return uuidIsValid, valUuidErr
	}
	return true, nil
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

// Validate IPv4 address
func ValidateMepCapabilityId(id string) error {
	if len(id) > maxMepCapabilityIdLen {
		return errors.New("MEP capability ID length exceeded max length 32")
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

// Validate file extenstion
func ValidateFileExtensionEmpty(fileName string) error {
	extension := filepath.Ext(fileName)
	if extension != "" {
		return errors.New("file shouldn't contains any extension")
	}
	return nil
}

// Validate file extenstion
func ValidateFileExtensionCsar(fileName string) error {
	extension := filepath.Ext(fileName)
	if extension != ".csar" {
		return errors.New("file extension is not csar")
	}
	return nil
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
		pwdValidCount := GetPasswordValidCount(password)
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
func GetPasswordValidCount(password *[]byte) int {
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
func ValidateAccessToken(accessToken string, allowedRoles []string, tenantId string) error {
	if accessToken == "" {
		return errors.New("require token")
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (interface{}, error) {
		return jwtPublicKey, nil
	})

	if token != nil && !token.Valid {
		err := validateTokenClaims(claims, allowedRoles,tenantId)
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
func validateTokenClaims(claims jwt.MapClaims, allowedRoles []string, userRequestTenantId string) error {
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

	if userRequestTenantId != "" {
		err = ValidateUserIdFromRequest(claims, userRequestTenantId)
		if err != nil {
			return err
		}
	}
	return nil
}

func ValidateUserIdFromRequest(claims jwt.MapClaims, userIdFromRequest string) error {

	userIdFromToken := ""
	log.Info(userIdFromToken)

	for key, value := range claims {
		if key == "userId" {
			userId := value.(interface{})
		    if userId != userIdFromRequest {
				log.Error("Illegal TenantId")
				return errors.New(IllegalTenantId)
			}
		}
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
				}
			}
			if !isRoleAllowed(roleName, allowedRoles) {
				log.Info("Invalid token A")
				return errors.New(InvalidToken)
			}
		}
	}
	return  nil
}

func isRoleAllowed(actual string, allowed []string) bool {
	for _, v := range allowed {
		if v == actual {
			return true
		}
	}
	return false
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
	cipherSuites := GetCipherSuites(sslCiphers)
	if cipherSuites == nil {
		return nil, errors.New("TLS cipher configuration is not recommended or invalid")
	}
	return &tls.Config{
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: cipherSuites,
		ServerName:   GetAppConfig("serverName"),
		InsecureSkipVerify: true,
	}, nil
}

// To get cipher suites
func GetCipherSuites(sslCiphers string) []uint16 {
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

// Validate port
func ValidatePort(port string) (bool, error) {
	portIsValid, validatePortErr := regexp.MatchString(PortRegex, port)
	if validatePortErr != nil || !portIsValid {
		return portIsValid, validatePortErr
	}
	return true, nil
}

// Validate service name
func ValidateServiceName(serviceName string) (bool, error) {
	serviceNameIsValid, valServiceNameErr := regexp.MatchString(SericeNameRegex, serviceName)
	hostIpIsValid, hostIpNameErr := regexp.MatchString(HostRegex, serviceName)
	if (valServiceNameErr != nil || !serviceNameIsValid) && (hostIpNameErr != nil || !hostIpIsValid) {
		return serviceNameIsValid, valServiceNameErr
	}
	return true, nil
}

// Get db user
func GetDbUser() string {
	dbUser := os.Getenv("LCM_CNTLR_USER")
	if dbUser == "" {
		dbUser = dbuser
	}
	return dbUser
}

// Get database name
func GetDbName() string {
	dbName := os.Getenv("LCM_CNTLR_DB")
	if dbName == "" {
		dbName = dbname
	}
	return dbName
}

// Get database host
func GetDbHost() string {
	dbHost := os.Getenv("LCM_CNTLR_DB_HOST")
	if dbHost == "" {
		dbHost = dbhost
	}
	return dbHost
}

// Get database port
func GetDbPort() string {
	dbPort := os.Getenv("LCM_CNTLR_DB_PORT")
	if dbPort == "" {
		dbPort = dbport
	}
	return dbPort
}

// Get prometheus port
func GetPrometheusPort() string {
	prometheusPort := os.Getenv("PROMETHEUS_PORT")
	if prometheusPort == "" {
		prometheusPort = prometheusport
	}
	return prometheusPort
}

// Get mep port
func GetMepPort() string {
	mepPort := os.Getenv("MEP_PORT")
	if mepPort == "" {
		mepPort = mepport
	}
	return mepPort
}

// Get k8splugin address
func GetK8sPlugin() string {
	k8sPlugin := os.Getenv(K8sPlugin)
	if k8sPlugin == "" {
		k8sPlugin = k8splugin
	}
	return k8sPlugin
}

// Get k8splugin port
func GetK8sPluginPort() string {
	k8sPluginPort := os.Getenv(K8sPluginPort)
	if k8sPluginPort == "" {
		k8sPluginPort = k8spluginport
	}
	return k8sPluginPort
}

// Does https request
func DoRequest(req *http.Request) (*http.Response, error) {
	config, err := TLSConfig("DB_SSL_ROOT_CERT")
	if err != nil {
		log.Error("Unable to send request")
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: config,
	}
	client := &http.Client{Transport: tr}

	return client.Do(req)
}

// Get API Gateway address
func GetAPIGwAddr() string {
	apiGwAddr := os.Getenv(ApiGwAddr)
	if apiGwAddr == "" {
		apiGwAddr = apigwAddr
	}
	return apiGwAddr
}

// Get API Gateway port
func GetAPIGwPort() string {
	apiGwPort := os.Getenv(ApiGwPort)
	if apiGwPort == "" {
		apiGwPort = apigwPort
	}
	return apiGwPort
}

// Get hostinfo
func GetHostInfo(url string) (string, error) {
	var resp *http.Response
	var err error

	var queryString string
	if strings.Contains(url, "capabilities") {
		queryString = "query_ssl_enable"
	} else {
		queryString = "query_kpi_ssl_enable"
	}

	if GetAppConfig(queryString) == "true" {
		url = HttpsUrl + url
		req, errNewRequest := http.NewRequest("", url, nil)
		if errNewRequest != nil {
			return "", errNewRequest
		}
		resp, err = DoRequest(req)
		if err != nil {
			return "", err
		}
	} else {
		url = HttpUrl + url
		resp, err = http.Get(url)
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	log.Info("response is received")

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return string(body), nil
	}
	return "", errors.New("created failed, status is " + strconv.Itoa(resp.StatusCode))
}

func GetPromethuesServiceName() string {
	promethuesServerName := os.Getenv(PromethuesServerName)
	if promethuesServerName == "" {
		promethuesServerName = PromethuesServerName
	}
	return promethuesServerName
}

// Validate app name
func ValidateAppName(appName string) (bool, error) {
	appNameIsValid, valAppNameErr := regexp.MatchString(AppNameRegex, appName)
	if valAppNameErr != nil || !appNameIsValid {
		return appNameIsValid, valAppNameErr
	}
	return true, nil
}

// Handle number of REST requests per second
func RateLimit(r *RateLimiter, ctx *context.Context) {
	var (
		limiterCtx limiter.Context
		err        error
		req        = ctx.Request
	)

	limiterCtx, err = r.GeneralLimiter.Get(req.Context(), "")
	if err != nil {
		ctx.Abort(http.StatusInternalServerError, err.Error())
		return
	}

	h := ctx.ResponseWriter.Header()
	h.Add("X-RateLimit-Limit", strconv.FormatInt(limiterCtx.Limit, 10))
	h.Add("X-RateLimit-Remaining", strconv.FormatInt(limiterCtx.Remaining, 10))
	h.Add("X-RateLimit-Reset", strconv.FormatInt(limiterCtx.Reset, 10))

	if limiterCtx.Reached {
		log.Infof("Too Many Requests on %s", ctx.Input.URL())
		ctx.Abort(http.StatusTooManyRequests, "429")
		return
	}
}
