FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get -y install make gcc glibc-source valgrind bash inetutils-ping libnl-3-dev git

#docker run -it -v "$(pwd):/home/ft_ping" debian-dev:latest bash