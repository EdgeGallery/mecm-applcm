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
FROM base AS development

ENV HOME=/usr/app

RUN apt-get update && \
    apt-get install -y python3-pip python3-dev gcc libpq-dev && \
    python3 -m venv /venv && \
    $HOME/venv/bin/pip3 install --upgrade pip

COPY . $HOME

WORKDIR $HOME

RUN $HOME/venv/bin/pip3 install -r $HOME/requirements.txt

RUN chmod -R 550 $HOME/core $HOME/internal $HOME/service $HOME/task $HOME/venv &&\
    chmod 550 $HOME/*.py $HOME/configs/start.sh
    chmod 640 $HOME/conf/config-pro.ini

# 构建运行时镜像
FROM base

RUN sed -i "s|umask 022|umask 027|g" /etc/profile
RUN mkdir -p /usr/app/log /usr/app/config /usr/app/package

ENV HOME=/usr/app
ENV UID=166
ENV GID=166
ENV USER_NAME=eguser
ENV GROUP_NAME=eggroup
ENV ENV="/etc/profile"

RUN groupadd -r -g $GID $GROUP_NAME &&\
    useradd -r -u $UID -g $GID -d $HOME -s /sbin/nologin -c "Docker image user" $USER_NAME

WORKDIR $HOME

RUN chmod 750 $HOME &&\
    chmod 550 -R $HOME/bin &&\
    mkdir -p -m 700 $HOME/ssl &&\
    mkdir -p -m 750 $HOME/log &&\
    mkdir -p -m 750 $HOME/config &&\
    mkdir -p -m 750 $HOME/package &&\
    chown -hR $USER_NAME:$GROUP_NAME $HOME

COPY --from=development --chown=$USER_NAME:$GROUP_NAME $HOME/core $HOME/core
COPY --from=development --chown=$USER_NAME:$GROUP_NAME $HOME/internal $HOME/internal
COPY --from=development --chown=$USER_NAME:$GROUP_NAME $HOME/service $HOME/service
COPY --from=development --chown=$USER_NAME:$GROUP_NAME $HOME/task $HOME/task
COPY --from=development --chown=$USER_NAME:$GROUP_NAME $HOME/*.py $HOME/
COPY --from=development --chown=$USER_NAME:$GROUP_NAME $HOME/conf/config-pro.ini $HOME/config.ini
COPY --from=development --chown=$USER_NAME:$GROUP_NAME $HOME/start.sh $HOME/bin
COPY --from=development --chown=$USER_NAME:$GROUP_NAME /venv $HOME/venv

USER $USER_NAME

EXPOSE 8234

CMD ["sh", "-c", "$HOME/bin/start.sh"]
