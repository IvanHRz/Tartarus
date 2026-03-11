FROM nginx:1.27-alpine

RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/tartarus.conf
COPY src/ /usr/share/nginx/html/

RUN apk add --no-cache curl

EXPOSE 80
