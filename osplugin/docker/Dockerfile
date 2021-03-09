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

FROM ubuntu:20.04 AS base

RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y python3 python3-pip python3-venv python3-dev gcc libpq-dev


FROM base AS builder

RUN python3 -m venv /venv && \
/venv/bin/pip3 install --upgrade pip -i https://mirrors.aliyun.com/pypi/simple
COPY requirements.txt /requirements.txt

RUN /venv/bin/pip3 install -r /requirements.txt -i https://mirrors.aliyun.com/pypi/simple


FROM base

WORKDIR /app

COPY core ./core
COPY internal ./internal
COPY service ./service
COPY *.py ./

COPY --from=builder /venv ./venv

CMD ./venv/bin/python3 run.py