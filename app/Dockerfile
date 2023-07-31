FROM python:3.10-slim
LABEL maintainer="greg.dresing@gmail.com"

RUN apt-get update
RUN apt-get install gcc -y
RUN apt-get install libpcre3 libpcre3-dev -y
RUN apt-get install libpq-dev -y

COPY ./app/requirements.txt /app/requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install --no-cache-dir -r /app/requirements.txt --src usr/local/src

WORKDIR /app

EXPOSE 5432

CMD [ "uwsgi", "--ini", "/app/uwsgi.ini" ]