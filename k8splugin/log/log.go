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

// Beego log related configurations
package log

import (
	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
	"k8splugin/util"
	"os"
)

func init() {
	fileName := "/usr/app/log/k8splugin.log"
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err == nil {
		defer file.Close()
		ioWriter := &lumberjack.Logger{
			Filename:   fileName,
			MaxSize:    util.MaxSize,   // megabytes
			MaxBackups: util.MaxBackups,   // max archived files
			MaxAge:     util.MaxAge,   // days
			Compress:   util.Compress, // compression
		}
		logrus.SetOutput(ioWriter)
	} else {
		logrus.Warn("Failed to log to file, using default stderr")
	}
	logrus.SetLevel(logrus.InfoLevel)
}
