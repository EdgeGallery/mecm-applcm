#!/bin/sh
# Copyright 2021 Huawei Technologies Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# validate host name
validate_host_name() {
  hostname="$1"
  len="${#hostname}"
  if [ "${len}" -gt "253" ]; then
    return 1
  fi
  if ! echo "$hostname" | grep -qE '^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$'; then
    return 1
  fi
  return 0
}

# validate name
validate_name() {
  hostname="$1"
  len="${#hostname}"
  if [ "${len}" -gt "64" ]; then
    return 1
  fi
  if ! echo "$hostname" | grep -qE '^[a-zA-Z0-9]*$|^[a-zA-Z0-9][a-zA-Z0-9_\-]*[a-zA-Z0-9]$'; then
    return 1
  fi
  return 0
}

# Validating if port is > 1 and < 65535 , not validating reserved port.
validate_port_num() {
  portnum="$1"
  len="${#portnum}"
  if [ "${len}" -gt "5" ]; then
    return 1
  fi
  if ! echo "$portnum" | grep -qE '^-?[0-9]+$'; then
    return 1
  fi
  if [ "$portnum" -gt "65535" ] || [ "$portnum" -lt "1" ]; then
    return 1
  fi
  return 0
}

# db parameters validation
if [ ! -z "$LCM_CNTLR_DB" ]; then
  validate_name "$LCM_CNTLR_DB"
  valid_name="$?"
  if [ ! "$valid_name" -eq "0" ]; then
    echo "invalid DB name"
    exit 1
  fi
else
  export LCM_CNTLR_DB=lcmcontrollerdb
fi

# db parameters validation
if [ ! -z "$LCM_CNTLR_USER" ]; then
  validate_name "$LCM_CNTLR_USER"
  valid_name="$?"
  if [ ! "$valid_name" -eq "0" ]; then
    echo "invalid DB user name"
    exit 1
  fi
else
  export LCM_CNTLR_USER=lcmcontroller
fi

if [ ! -z "$LCM_CNTLR_DB_HOST" ]; then
  validate_host_name "$LCM_CNTLR_DB_HOST"
  valid_db_host_name="$?"
  if [ ! "$valid_db_host_name" -eq "0" ]; then
    echo "invalid db host name"
    exit 1
  fi
else
  export LCM_CNTLR_DB_HOST=mepm-postgres
fi

if [ ! -z "$LCM_CNTLR_DB_PORT" ]; then
  validate_port_num "$LCM_CNTLR_DB_PORT"
  valid_LCMCONTROLLER_db_port="$?"
  if [ ! "$valid_LCMCONTROLLER_db_port" -eq "0" ]; then
    echo "invalid LCMcontroller db port number"
    exit 1
  fi
else
  export LCM_CNTLR_DB_PORT=5432
fi

if [ ! -z "$OPENSTACK_PLUGIN" ]; then
  validate_host_name "$OPENSTACK_PLUGIN"
  valid_openstack_plugin_host_name="$?"
  if [ ! "$valid_openstack_plugin_host_name" -eq "0" ]; then
    echo "invalid openstack plugin host name"
    exit 1
  fi
else
  export OPENSTACK_PLUGIN=mecm-mepm-osplugin
fi

if [ ! -z "$OPENSTACK_PLUGIN_PORT" ]; then
  validate_port_num "$OPENSTACK_PLUGIN_PORT"
  valid_openstack_plugin_port="$?"
  if [ ! "$valid_openstack_plugin_port" -eq "0" ]; then
    echo "invalid OPENSTACK plugin port number"
    exit 1
  fi
else
  export OPENSTACK_PLUGIN_PORT=8234
fi

sed -i "s/^HTTPSAddr.*=.*$/HTTPSAddr = $(hostname -i)/g" conf/app.conf
sed -i "s/^isHTTPS.*=.*$/isHTTPS = $(IS_HTTPS)/g" conf/app.conf

cd /usr/app
umask 0027
$HOME/bin/rescontroller