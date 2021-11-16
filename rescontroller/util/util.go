/*
 * Copyright 2021 Huawei Technologies Co., Ltd.
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
	AuthorizationFailed      string = "Authorization failed"
	Default                  string = "default"
	DriverName               string = "postgres"
	Failure                  string = "Failure"
	ClientIpaddressInvalid          = "clientIp address is invalid"
	FailedToUnmarshal        string = "failed to unmarshal request"
	MecHostRecDoesNotExist   string = "Mec host info record does not exist in database"
	FailedToCreateClient     string = "failed to create client: %v"
	InvalidToken             string = "invalid token"
	Forbidden                string = "forbidden"
	IllegalTenantId          string = "Illegal TenantId"
	HostIp                          = "mec_host_id"
	FailedToGetClient               = "Failed to get client"
	FlavorId                        = ":flavorId"
	SecurityGroupId                 = ":securityGroupId"
	ServerId                        = ":serverId"

	RequestBodyTooLarge            = "request body too large"
	CreateFlavorSuccess            = "Create flavor is successful"
	DeleteFlavorSuccess            = "Delete flavor is successful"
	PluginErrorReport              = "Failed to do operate on Plugin"
	MaxSize                  int   = 20
	MaxBackups               int   = 50
	MaxAge                         = 30
	Timeout                        = 180

	BadRequest                int = 400
	StatusUnauthorized        int = 401
	StatusInternalServerError int = 500
	StatusNotFound            int = 404
	StatusForbidden           int = 403
	RequestBodyLength             = 4096

	MaxIPVal             = 255

	SuccessCode int = 200

	QueryImages                   = "/v1/tenants/:tenantId/hosts/:hostIp/images/:imageId"
	QueryServer                   = "/v1/tenants/:tenantId/hosts/:hostIp/servers/:serverId"

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

	NameRegex     = "^[\\d\\p{L}]*$|^[\\d\\p{L}][\\d\\p{L}_\\-]*[\\d\\p{L}]$"

	minPasswordSize         = 8
	maxPasswordSize         = 16
	specialCharRegex string = `['~!@#$%^&()-_=+\|[{}\];:'",<.>/?]`
	singleDigitRegex string = `\d`
	lowerCaseRegex   string = `[a-z]`
	upperCaseRegex   string = `[A-Z]`
	maxPasswordCount        = 2
	FailedToWriteRes        = "Failed to write response into context"

	MecmTenantRole       = "ROLE_MECM_TENANT"
	MecmAdminRole        = "ROLE_MECM_ADMIN"
	MecmGuestRole        = "ROLE_MECM_GUEST"
	Flavorcontroller     = "rescontroller/controllers:FlavorController"
	Networkcontroller    = "rescontroller/controllers:NetworkController"
	SecurityGroupcontroller    = "rescontroller/controllers:SecurityGroupController"
	VmImagecontroller    = "rescontroller/controllers:VmImageController"
	VmController         = "rescontroller/controllers:VmController"
	DELETE               = "delete"
	GET                  = "get"
	POST                 = "post"
	ResponseForClient    = 	"Response message for ClientIP ["
	Operation            = "] Operation ["
	Resource             = " Resource ["
	UserId               = "7f9cac8d-7c54-23e7-99c6-27e4d944d5de"
)

var ReadTlsCfg = true

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
	validate := validator.New()
	res := validate.Var(id, "required,uuid")
	if res != nil {
		return errors.New("UUID validate failed")
	}
	return nil
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

// Validate user name
func ValidateUserName(name string, regex string) (bool, error) {
	if len(name) > 15 {
		return false, errors.New("name length is larger than max size")
	}
	return regexp.MatchString(regex, name)
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

// Validate IPv4 address
func ValidateIpv4Address(id string) error {
	if id == "" {
		return errors.New("require ip address")
	}

	validate := validator.New()
	return validate.Var(id, "required,ipv4")
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
	return pluginInfo
}