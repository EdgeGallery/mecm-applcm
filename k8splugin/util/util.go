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
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"
	"os"
	"regexp"
)

var (
	jwtPublicKey        = os.Getenv("JWT_PUBLIC_KEY")
)

const DB_REGEX string = `^[\w-]{4,16}$`
const DB_USER_REGEX = DB_REGEX
const DB_NAME_REGEX = DB_REGEX
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
const HostIpIsInvalid = "HostIp is invalid"
const AccssTokenIsInvalid = "AccessToken is invalid"
const Success = "Success"
const Failure = "Failure"
const ActionConfig = "Unable to initialize action config"
const HelmDriver = "HELM_DRIVER"
const AppInsId = "app_ins_id"

// Validate server port
func ValidateServerPort(serverPort string) (bool, error) {
	serPortIsValid, validateSerPortErr := regexp.MatchString(PORT_REGEX, serverPort)
	if validateSerPortErr != nil || !serPortIsValid {
		return serPortIsValid, validateSerPortErr
	}
	return true, nil
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
