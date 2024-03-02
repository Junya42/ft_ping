FROM debian:bullseye

RUN apt-get update && \
    apt-get -y install make gcc glibc-source valgrind bash inetutils-ping

