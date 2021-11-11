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

package controllers

import log "github.com/sirupsen/logrus"

// security group Controller
type SecurityGroupController struct {
	BaseController
}

func (c *SecurityGroupController) CreateSecurityGroup() {
	log.Info("Create security group request received.")
}

func (c *SecurityGroupController) QuerySecurityGroup() {
	log.Info("Query security group request received.")
}

func (c *SecurityGroupController) DeleteSecurityGroup() {
	log.Info("Delete security group by security group id request received.")
}

func (c *SecurityGroupController) CreateSecurityGroupRules() {
	log.Info("Create security group rules request received.")
}

func (c *SecurityGroupController) QuerySecurityGroupRules() {
	log.Info("Query security group rules request received.")
}

func (c *SecurityGroupController) DeleteSecurityGroupRules() {
	log.Info("Delete security group rules by security group rules id request received.")
}
