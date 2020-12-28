FROM python:3.8-rc-stretch

WORKDIR /app

ADD . /app

ENV STATIC_INDEX 1

RUN pip3 install -r requirements.txt

CMD ["uwsgi", "app.ini"]