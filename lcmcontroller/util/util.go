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
	"github.com/satori/go.uuid"
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

const (
	AccessToken              string = "access_token"
	PluginSuffix             string = "_PLUGIN"
	PluginPortSuffix         string = "_PORT"
	MepServer                string = "MEP_SERVER"
	AuthorizationFailed      string = "Authorization failed"
	Default                  string = "default"
	DriverName               string = "postgres"
	Failure                  string = "Failure"
	ClientIpaddressInvalid          = "clientIp address is invalid"
	FailedToSendMetadataInfo string = "failed to send metadata information"
	FailedToUnmarshal        string = "failed to unmarshal request"
	FailedToMarshal          string = "failed to marshal request"
	LastInsertIdNotSupported string = "LastInsertId is not supported by this driver"
	MecHostRecDoesNotExist   string = "Mec host info record does not exist in database"
	FailedToCreateClient     string = "failed to create client: %v"
	InvalidToken             string = "invalid token"
	Forbidden                string = "forbidden"
	IllegalTenantId          string = "Illegal TenantId"
	AppInsId                        = "app_instance_id"
	AppPkgId                        = "app_pkg_id"
	AppPackageRecordId              = "app_package_record"
	PkgHostKey                      = "pkg_host_key"
	TenantId                        = "tenant_id"
	HostId                          = "mec_host_id"
	MecHostIp                       = "mechost_ip"
	Mec_Host                        = "mec_host"
	FailedToGetClient               = "Failed to get client"

	UserNameOrKeyInvalid           = "username or key is invalid"
	FailedToMakeDir                = "failed to make directory"
	FileNameNotFound               = "file name not found with "
	FailedToFindAppPackage         = "failed to find application package"
	FailedToReadAppPackage         = "failed to read application package"
	AppIdIsNotValid                = "AppName is invalid"
	FailedToReadMfFile             = "failed to read mf file"
	FailedToAnalysisMfFile         = "Failed to get info, pls check mf file if struct is not correct."
	AppNameIsNotValid              = "AppName is invalid"
	HostIpIsInvalid                = "MecHost address is invalid"
	PackageIdIsInvalid             = "package id is invalid"
	TenantIdIsInvalid              = "package id is invalid"
	OriginIsInvalid                = "Origin is invalid"
	RecordDoesNotExist             = "records does not exist"
	RequestBodyTooLarge            = "request body too large"
	FailedToUploadToPlugin         = "failed to upload package to plugin"
	UploadPackageSuccess           = "Uploaded application package successfully"
	FailedToInstantiate            = "failed to instantiate app"
	FailedToCovertYamlToJson       = "failed to convert yaml to json"
	NotFound                       = "not found"
	UploadConfigSuccess            = "Upload config is successful"
	GetPackageDetailsFailed        = "failed to get app package details"
	PluginErrorReport              = "Failed to do operate on Plugin"
	InsertDBWithError              = "Failed to insert data to DB"
	PackageNumUpToMax              = "Maximum number of app package records are exceeded for given tenant"
	TenantNumUpToMax               = "Maximum number of tenant records are exceeded"
	FailedToSaveAppInfo            = "Failed to save app info record to database."
	MaxSize                  int   = 20
	MaxBackups               int   = 50
	MaxAge                         = 30
	MaxConfigFile            int64 = 5242880
	MaxAppPackageFile        int64 = 536870912
	Timeout                        = 180
	MaxNumberOfRecords             = 500
	MaxNumberOfTenantRecords       = 20
	MaxNumberOfHostRecords         = 20
	MaxFileNameSize                = 128

	BadRequest                int = 400
	StatusUnauthorized        int = 401
	StatusInternalServerError int = 500
	StatusNotFound            int = 404
	StatusForbidden           int = 403
	RequestBodyLength             = 4096

	SuccessCode int = 200

	//Base Error Code
	ErrCodeForbidden         int = 31000
	ErrCodeTokenInvalid      int = 31001
	ErrCodeIPInvalid         int = 31002
	ErrCodeMecHostInvalid    int = 31003
	ErrCodeBodyTooLarge      int = 31005
	ErrCodeHostNotExist      int = 31006
	ErrCodeAppIdInvalid      int = 31007
	ErrCodePackageIdInvalid  int = 31008
	ErrCodeTenantIdInvalid   int = 31009
	ErrCodeAppNameInvalid    int = 31010
	ErrCodePackDistributed   int = 31012
	ErrCodeInstanceIsExist   int = 31013
	ErrCodeProcessAkSkFailed int = 31014
	ErrCodeHostNotFoundInPlg int = 31015
	ErrorReportByPlugin      int = 31016
	ErrCodeWriteResFailed    int = 31018
	ErrCodeInvalidCapId      int = 31020
	ErrCodeCallForMep        int = 31022
	ErrCodeFailedToMarshal   int = 31023
	ErrCodeFailedToUnMarshal int = 31024
	ErrCodeTenantNumUpToMax  int = 31025
	ErrCodeInvalidRequest    int = 31027
	ErrCodeOriginInvalid     int = 31029
	ErrCodeGetVimFailed      int = 31032
	ErrCodeDeleteFileFailed  int = 31034
	ErrCodeInstanceIdInvalid int = 31035

	//File Error Code
	ErrCodeFileCanNotRead   int = 31100
	ErrCodeFileNameTooLang  int = 31102
	ErrCodeFileToBig        int = 31103
	ErrCodeFailedToSaveFile int = 31104
	ErrCodeFailedToExtract  int = 31105
	ErrCodeFailedGetDetails int = 31106
	ErrCodePackNumUptoMax   int = 31107

	//Plugin Error Code
	ErrCodeFailedGetPlugin      int = 31201
	ErrCodePluginReportFailed   int = 31202
	ErrCodeGetWorkloadFailed    int = 31203
	ErrCodeFailedGetClient      int = 31204
	ErrCodeUploadToPluginFailed int = 31205
	ErrCodePluginNotFound       int = 31206

	//DB Error Code
	ErrCodeInsertDataFailed  int = 31300
	ErrCodeNotFoundInDB      int = 31301
	ErrCodeDeleteDataFailed  int = 31302
	ErrCodeRecordNotExist    int = 31303
	ErrCodeReportByDB        int = 31305
	ErrCodeSaveAppInfoFailed int = 31304

	//Instantiate Error Code
	ErrCodePluginInstFailed  int = 31601
	ErrCodeDeleteAuthCfgFail int = 31602

	ErrCodeInternalServer int = 31503
	ErrCodeBadRequest     int = 31400

	UuidRegex     = `^[a-fA-F0-9]{8}[a-fA-F0-9]{4}4[a-fA-F0-9]{3}[8|9|aA|bB][a-fA-F0-9]{3}[a-fA-F0-9]{12}$`
	NameRegex     = "^[\\d\\p{L}]*$|^[\\d\\p{L}][\\d\\p{L}_\\-]*[\\d\\p{L}]$"
	CityRegex     = "^[\\d\\p{L}]*$|^[\\d\\p{L}][\\d\\p{L}\\/\\s]*[\\d\\p{L}]$"
	AffinityRegex = "^[\\d\\p{L}]*$|^[\\d\\p{L}][\\d\\p{L}_\\-\\,]*[\\d\\p{L}]$"

	minPasswordSize         = 8
	maxPasswordSize         = 16
	specialCharRegex string = `['~!@#$%^&()-_=+\|[{}\];:'",<.>/?]`
	singleDigitRegex string = `\d`
	lowerCaseRegex   string = `[a-z]`
	upperCaseRegex   string = `[A-Z]`
	maxPasswordCount        = 2
	MaxIdLength             = 36

	TooManyFile      = 1024
	TooBig           = 0x6400000
	SingleFileTooBig = 0x6400000

	HttpUrl          string = "http://"
	HttpsUrl         string = "https://"
	CpuQuery         string = "/api/v1/query?query=sum(kube_pod_container_resource_requests_cpu_cores)/sum(kube_node_status_allocatable_cpu_cores)"
	MemQuery         string = "/api/v1/query?query=sum(kube_pod_container_resource_requests_memory_bytes)/sum(kube_node_status_allocatable_memory_bytes)"
	DiskQuery        string = "/api/v1/query?query=(sum(node_filesystem_size_bytes)-sum(node_filesystem_free_bytes))/sum(node_filesystem_size_bytes)"
	UnexpectedValue         = "unexpected value found"
	MarshalError            = "Failed to marshal json"
	UnMarshalError          = "Failed to unmarshal json"
	FailedToWriteRes        = "Failed to write response into context"
	CapabilityUri           = "/mepcfg/mec_platform_config/v1/capabilities"
	ApiGwAddr               = "API_GW_ADDR"
	ApiGwPort               = "API_GW_PORT"

	MecmTenantRole       = "ROLE_MECM_TENANT"
	MecmAdminRole        = "ROLE_MECM_ADMIN"
	MecmGuestRole        = "ROLE_MECM_GUEST"
	UserId               = "7f9cac8d-7c54-23e7-99c6-27e4d944d5de"
	MaxIPVal             = 255
	PrometheusServerName = "PROMETHEUS_SERVER_NAME"
	AccessTokenIsInvalid = "accessToken is invalid"
	Lcmcontroller        = "lcmcontroller/controllers:LcmController"
	Lcmcontrollerv2      = "lcmcontroller/controllers:LcmControllerV2"
	MecHostcontroller    = "lcmcontroller/controllers:MecHostController"
	Mepcontroller        = "lcmcontroller/controllers:MepController"
	Hosts                = "/v1/tenants/:tenantId/hosts"
	AllHosts             = "/v1/hosts"
	DELETE               = "delete"
	GET                  = "get"
	POST                 = "post"
	ResponseForClient    = "Response message for ClientIP ["
	Operation            = "] Operation ["
	Resource             = " Resource ["
	TempFile             = "/usr/app/temp"
	ApplicationJson      = "application/json"
	ContentType          = "Content-Type"
	Accept               = "Accept"
	MecHostInfo          = "MecHostInfo"
	PkgId                = "package_id"
	PkgUrlPath           = "/v1/tenants/:tenantId/packages/:packageId"

	PkgUrlPathV2         = "/v2/tenants/:tenantId/packages/:packageId"
	QueryMepCapabilities = "/v2/tenants/:tenantId/hosts/:hostIp/mep_capabilities"

	//mep service calling
	ErrCallFromMep        string = "failed to execute rest calling, check if mep service is ready."
	MepServiceQuery       string = "https://mep-mm5.mep:80/mep/service_govern/v1/services"
	MepKongLogQuery       string = "https://mep-mm5.mep:80/mep/service_govern/v1/kong_log"
	MepSubscribeStatistic string = "https://mep-mm5.mep:80/mep/service_govern/v1/subscribe_statistic"

	PkgDtlMetadata       = "metadata"
	PkgDtlAppName        = "app_product_name"
	PkgDtlAppId          = "app_provider_id"
	PkgDtlAppVersion     = "app_package_version"
	PkgDtlAppRlsTime     = "app_release_data_time"
	PkgDtlAppType        = "app_type"
	PkgDtlAppClass       = "app_class"
	PkgDtlAppDescription = "app_package_description"
	UnderScore           = "_"
)

var ReadTlsCfg = true
var VmImageMap = make(map[int32][]byte, 150000)

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
		return errors.New("require id")
	}
	validate := validator.New()
	res := validate.Var(id, "required,uuid")
	if res != nil {
		return errors.New("UUID validate failed")
	}
	return nil
}

// Validate IPv4 address
func ValidateIpv4Address(id string) error {
	if id == "" {
		return errors.New("require ip address")
	}

	validate := validator.New()
	return validate.Var(id, "required,ipv4")
}

// Validate source address
func ValidateSrcAddress(id string) error {
	if id == "" {
		return errors.New("require ip address")
	}

	validate := validator.New()
	err := validate.Var(id, "required,ipv4")
	if err != nil {
		return validate.Var(id, "required,ipv6")
	}
	return nil
}

// Validate IPv4 address
func ValidateMepCapabilityId(id string) error {
	if len(id) > MaxIdLength {
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
	if extension != ".csar" && extension != ".zip" {
		return errors.New("file extension is not csar or zip")
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
func ValidateDbParams(dbPwd string) (bool, error) {
	dbPwdBytes := []byte(dbPwd)
	dbPwdIsValid, validateDbPwdErr := ValidatePassword(&dbPwdBytes)
	if validateDbPwdErr != nil || !dbPwdIsValid {
		return dbPwdIsValid, validateDbPwdErr
	}
	return true, nil
}

// Validate access token
func ValidateAccessToken(accessToken string, allowedRoles []string, tenantId string) error {
	if accessToken == "" {
		return nil
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (interface{}, error) {
		return jwtPublicKey, nil
	})

	if token != nil && !token.Valid {
		err := validateTokenClaims(claims, allowedRoles, tenantId)
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

func ValidateRole(claims jwt.MapClaims, allowedRoles []string) error {
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
			err := isValidUser(roleName, allowedRoles)
			if err != nil {
				log.Info("not authorised user")
				return err
			}
		}
	}
	return nil
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
		RootCAs:            rootCAs,
		MinVersion:         tls.VersionTLS12,
		CipherSuites:       cipherSuites,
		ServerName:         GetAppConfig("serverName"),
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

// Get db user
func GetDbUser() string {
	dbUser := os.Getenv("LCM_CNTLR_USER")
	return dbUser
}

// Get database name
func GetDbName() string {
	dbName := os.Getenv("LCM_CNTLR_DB")
	return dbName
}

// Get database host
func GetDbHost() string {
	dbHost := os.Getenv("LCM_CNTLR_DB_HOST")
	return dbHost
}

// Get database port
func GetDbPort() string {
	dbPort := os.Getenv("LCM_CNTLR_DB_PORT")
	return dbPort
}

// Get prometheus port
func GetPrometheusPort() string {
	prometheusPort := os.Getenv("PROMETHEUS_PORT")
	return prometheusPort
}

// Get mep server address
func GetMepServerAddress() string {
	mepServer := os.Getenv(MepServer)
	return mepServer
}

// Get mep port
func GetMepPort() string {
	mepPort := os.Getenv("MEP_PORT")
	return mepPort
}

// Get plugin address
func GetPluginAddress(plugin string) string {
	pluginAddr := os.Getenv(plugin)
	if pluginAddr == "" {
		log.Error("Plugin address couldn't be found for : " + plugin)
	}
	return pluginAddr
}

// Get plugin port
func GetPluginPort(portVar string) string {
	pluginPort := os.Getenv(portVar)
	if pluginPort == "" {
		log.Error("Plugin port couldn't be found for : " + portVar)
	}
	return pluginPort
}

// Get API Gateway address
func GetAPIGwAddr() string {
	apiGwAddr := os.Getenv(ApiGwAddr)
	return apiGwAddr
}

// Get API Gateway port
func GetAPIGwPort() string {
	apiGwPort := os.Getenv(ApiGwPort)
	return apiGwPort
}

// Get prometheus service name
func GetPrometheusServiceName() string {
	prometheusServerName := os.Getenv(PrometheusServerName)
	return prometheusServerName
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

// Get hostinfo
func GetHostInfo(url string) (string, int, error) {
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
			return "", StatusInternalServerError, errNewRequest
		}
		resp, err = DoRequest(req)
		if err != nil {
			return "", StatusInternalServerError, err
		}
	} else {
		url = HttpUrl + url
		resp, err = http.Get(url)
		if err != nil {
			return "", StatusInternalServerError, err
		}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	log.Info("response is received")

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return string(body), resp.StatusCode, nil
	}
	return "", resp.StatusCode, errors.New("created failed, status is " + strconv.Itoa(resp.StatusCode))
}

// Validate app name
func ValidateName(name string, regex string) (bool, error) {
	if len(name) > 128 {
		return false, errors.New("name length is larger than max size")
	}
	return regexp.MatchString(regex, name)
}

// Validate app name
func ValidateUserName(name string, regex string) (bool, error) {
	if len(name) > 15 {
		return false, errors.New("name length is larger than max size")
	}
	return regexp.MatchString(regex, name)
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

// Get Prometheus service name and port
func GetPrometheusServiceNameAndPort() (string, string) {
	prometheusServiceName := GetPrometheusServiceName()
	prometheusPort := GetPrometheusPort()
	return prometheusServiceName, prometheusPort
}

// Get plugin info
func GetPluginInfo(vim string) string {
	// Default case of kubernetes for backward compatibility
	if vim == "" {
		vim = "k8s"
	}
	pluginAddrVar := strings.ToUpper(vim) + PluginSuffix
	pluginAddr := GetPluginAddress(pluginAddrVar)
	pluginPortVar := pluginAddrVar + PluginPortSuffix
	pluginPort := GetPluginPort(pluginPortVar)
	pluginInfo := pluginAddr + ":" + pluginPort
	log.Info("pluginInfo is: " + pluginInfo)
	return pluginInfo
}

func GenerateUUID() string {
	uuId := uuid.NewV4()
	return strings.Replace(uuId.String(), "-", "", -1)
}

func IsAdminRole(accessToken string) bool {
	claims := jwt.MapClaims{}

	token, _ := jwt.ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (interface{}, error) {
		return jwtPublicKey, nil
	})
	if token != nil && !token.Valid {
		for key, value := range claims {
			if key == "authorities" {
				authorities := value.([]interface{})
				arr := reflect.ValueOf(authorities)
				for i := 0; i < arr.Len(); i++ {
					if arr.Index(i).Interface() == MecmAdminRole {
						return true
					}
				}
			}
		}
	}
	return false
}
