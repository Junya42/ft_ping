FROM debian:bullseye

RUN apt-get update && \
    apt-get -y install make gcc glibc-source valgrind bash inetutils-ping libnl-3-dev

#docker run -it -v "$(pwd):/home/ft_ping" debian-dev:latest bash
