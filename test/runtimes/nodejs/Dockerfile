# Compile the proctor binary.
FROM golang:1.12 AS golang
COPY common $GOPATH/src/gvisor.dev/gvisor/test/runtimes/common/common
COPY nodejs/proctor-nodejs.go ${LANG_DIR}
RUN ["go", "build", "-o", "/proctor", "proctor-nodejs.go"]

FROM ubuntu:bionic
ENV LANG_VER=12.4.0
ENV LANG_NAME=Node

RUN apt-get update && apt-get install -y \
  curl \
  dumb-init \
  g++ \
  make \
  python

WORKDIR /root
RUN curl -o node-v${LANG_VER}.tar.gz https://nodejs.org/dist/v${LANG_VER}/node-v${LANG_VER}.tar.gz
RUN tar -zxf node-v${LANG_VER}.tar.gz
ENV LANG_DIR=/root/node-v${LANG_VER}

WORKDIR ${LANG_DIR}
RUN ./configure
RUN make
RUN make test-build

COPY --from=golang /proctor /proctor

# Including dumb-init emulates the Linux "init" process, preventing the failure
# of tests involving worker processes.
ENTRYPOINT ["/usr/bin/dumb-init", "/proctor"]
