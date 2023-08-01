FROM nginx

RUN rm /etc/nginx/conf.d/default.conf

EXPOSE 443

COPY ./nginx/nginx.conf /etc/nginx/
COPY ./nginx/startapi.sh /etc/nginx

WORKDIR /etc/nginx

RUN [ "chmod", "+x", "startapi.sh" ]

ENTRYPOINT [ "./startapi.sh" ]