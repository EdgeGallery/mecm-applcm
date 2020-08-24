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
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
	"os"
	"regexp"
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
const Failure string = "Failure"
const FailedToSendMetadataInfo string = "failed to send metadata information: %v"
const FailedToCreateClient string = "failed to create client: %v"
const InvalidToken string = "invalid token"
const MaxSize int = 20
const MaxBackups int = 50
const MaxAge = 30
const MaxConfigFile int64 = 5242880

const BadRequest int = 400
const StatusUnauthorized int = 401
const StatusInternalServerError int = 500

const DB_REGEX string = `^[\w-]{4,16}$`
const DB_USER_REGEX = DB_REGEX
const DB_PWD_REGEX = DB_REGEX
const DB_NAME_REGEX = DB_REGEX
const HOST_REGEX string = `^[\w-.]{4,16}$`
const PORT_REGEX string = `^[0-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]$`

// Validate UUID
func ValidateUUID(id string) error {
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

// Validate db paramters
func ValidateDbParams(dbUser string, dbPwd string, dbName string, dbHost string, dbPort string) (bool, error) {
	dbUserIsValid, validateDbUserErr := regexp.MatchString(DB_USER_REGEX, dbUser)
	if validateDbUserErr != nil || !dbUserIsValid {
		return dbUserIsValid, validateDbUserErr
	}
	dbPwdIsValid, validateDbPwdErr := regexp.MatchString(DB_PWD_REGEX, dbPwd)
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
