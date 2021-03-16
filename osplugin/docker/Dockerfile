# Copyright 2021 21CN Corporation Limited
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

# 构建ubuntu python3基础镜像
FROM ubuntu:20.04 AS base

RUN apt-get update && \
    apt-get install -y python3 python3-venv libpq5

# 构建pip3依赖镜像并下载依赖
FROM base AS developement

RUN apt-get update && \
    apt-get install -y python3-pip python3-dev gcc libpq-dev && \
    python3 -m venv /venv && \
    /venv/bin/pip3 install --upgrade pip

COPY requirements.txt /requirements.txt

RUN /venv/bin/pip3 install -r /requirements.txt

# 构建运行时镜像
FROM base

WORKDIR /usr/app

COPY core ./core
COPY internal ./internal
COPY service ./service
COPY *.py ./

COPY --from=developement /venv ./venv

CMD ./venv/bin/python3 run.py
