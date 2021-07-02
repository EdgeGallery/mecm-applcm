#!/bin/sh
# Copyright 2020 Huawei Technologies Co., Ltd.
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
    echo "invalid lcmcontroller db port number"
    exit 1
  fi
else
  export LCM_CNTLR_DB_PORT=5432
fi

if [ ! -z "$PROMETHEUS_PORT" ]; then
  validate_port_num "$PROMETHEUS_PORT"
  valid_PROMETHEUS_db_port="$?"
  if [ ! "$valid_PROMETHEUS_db_port" -eq "0" ]; then
    echo "invalid PROMETHEUS port number"
    exit 1
  fi
else
  export PROMETHEUS_PORT=80
fi

if [ ! -z "$MEP_SERVER" ]; then
  validate_host_name "$MEP_SERVER"
  valid_mep_server_addr="$?"
  if [ ! "$valid_mep_server_addr" -eq "0" ]; then
    echo "invalid mep server addr"
    exit 1
  fi
else
  export MEP_SERVER=mep-mm5.mep
fi

if [ ! -z "$MEP_PORT" ]; then
  validate_port_num "$MEP_PORT"
  valid_MEP_db_port="$?"
  if [ ! "$valid_MEP_db_port" -eq "0" ]; then
    echo "invalid MEP port number"
    exit 1
  fi
else
  export MEP_PORT=80
fi

if [ ! -z "$K8S_PLUGIN" ]; then
  validate_host_name "$K8S_PLUGIN"
  valid_k8s_plugin_host_name="$?"
  if [ ! "$valid_k8s_plugin_host_name" -eq "0" ]; then
    echo "invalid K8s plugin host name"
    exit 1
  fi
else
  export K8S_PLUGIN=mecm-mepm-k8splugin
fi

if [ ! -z "$K8S_PLUGIN_PORT" ]; then
  validate_port_num "$K8S_PLUGIN_PORT"
  valid_k8s_plugin_port="$?"
  if [ ! "$valid_k8s_plugin_port" -eq "0" ]; then
    echo "invalid K8S plugin port number"
    exit 1
  fi
else
  export K8S_PLUGIN_PORT=8095
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

if [ ! -z "$API_GW_ADDR" ]; then
  validate_host_name "$API_GW_ADDR"
  valid_api_gw_addr="$?"
  if [ ! "$valid_api_gw_addr" -eq "0" ]; then
    echo "invalid api gw addr"
    exit 1
  fi
else
  export API_GW_ADDR=mepauth.mep
fi

if [ ! -z "$API_GW_PORT" ]; then
  validate_port_num "$API_GW_PORT"
  valid_api_gw_port="$?"
  if [ ! "$valid_api_gw_port" -eq "0" ]; then
    echo "invalid api gw port number"
    exit 1
  fi
else
  export API_GW_PORT=10443
fi


if [ ! -z "$PROMETHEUS_SERVER_NAME" ]; then
  validate_host_name "$PROMETHEUS_SERVER_NAME"
  valid_prometheus_service="$?"
  if [ ! "$valid_prometheus_service" -eq "0" ]; then
    echo "invalid prometheus service"
    exit 1
  fi
else
  export PROMETHEUS_SERVER_NAME=mep-prometheus-server
fi

sed -i "s/^HTTPSAddr.*=.*$/HTTPSAddr = $(hostname -i)/g" conf/app.conf
sed -i "s/^isHTTPS.*=.*$/isHTTPS = $(IS_HTTPS)/g" conf/app.conf

cd /usr/app
umask 0027
$HOME/bin/lcmcontroller