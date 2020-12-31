FROM python:3.8-rc-slim

COPY ./financeapp/requirements.txt /app/requirements.txt

WORKDIR /app
RUN apt-get clean \
    && apt-get -y update \
    && pip install --upgrade pip  \
    && apt-get -y install python3-dev \
    && apt-get -y install build-essential \
    && pip install -r requirements.txt \
    && rm -rf /var/cache/apk/*

COPY ./financeapp /app

CMD ["uwsgi", "--ini", "app.ini"]