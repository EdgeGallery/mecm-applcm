FROM ht-hub.21cn.com/library/python3:ubuntu-20.04 as builder

ENV HOME=/usr/app

RUN apt-get update && apt-get install python3-dev gcc libc-dev

RUN mkdir -p $HOME

WORKDIR /python3/cache

COPY requirements.txt .

RUN python3 -m venv ./venv && source ./venv/bin/activate && pip3 install -r requirements.txt

COPY . $HOME

FROM python3:alpine

WORKDIR $HOME

COPY --from=builder $HOME/venv $HOME/venv
COPY --from=builder $HOME/configs $HOME/configs
COPY --from=builder $HOME/core $HOME/core
COPY --from=builder $HOME/internal $HOME/internal
COPY --from=builder $HOME/service $HOME/service
COPY --from=builder $HOME/config.py $HOME/config.py
COPY --from=builder $HOME/run.py $HOME/run.py
COPY --from=builder $HOME/utils.py $HOME/utils.py

EXPOSE 8234

CMD ["sh", "-c", "$HOME/bin/start.sh"]