# Compile the proctor binary.
FROM golang:1.12 AS golang
COPY common $GOPATH/src/gvisor.dev/gvisor/test/runtimes/common/common
COPY php/proctor-php.go ${LANG_DIR}
RUN ["go", "build", "-o", "/proctor", "proctor-php.go"]

FROM ubuntu:bionic
ENV LANG_VER=7.3.6
ENV LANG_NAME=PHP

RUN apt-get update && apt-get install -y \
  autoconf \
  automake \
  bison \
  build-essential \
  curl \
  libtool \
  libxml2-dev \
  re2c

WORKDIR /root
RUN curl -o php-${LANG_VER}.tar.gz https://www.php.net/distributions/php-${LANG_VER}.tar.gz
RUN tar -zxf php-${LANG_VER}.tar.gz
ENV LANG_DIR=/root/php-${LANG_VER}

WORKDIR ${LANG_DIR}
RUN ./configure
RUN make

COPY --from=golang /proctor /proctor
ENTRYPOINT ["/proctor"]
