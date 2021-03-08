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