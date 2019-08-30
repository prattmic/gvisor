# Compile the proctor binary.
FROM golang:1.12 AS golang
COPY common $GOPATH/src/gvisor.dev/gvisor/test/runtimes/common/common
COPY java/proctor-java.go ${LANG_DIR}
RUN ["go", "build", "-o", "/proctor", "proctor-java.go"]

FROM ubuntu:bionic
ENV LANG_VER=3.7.3
ENV LANG_NAME=Python
ENV LANG_DIR=/root/cpython-${LANG_VER}

RUN apt-get update && apt-get install -y \
  curl \
  gcc \
  libbz2-dev \
  libffi-dev \
  liblzma-dev \
  libreadline-dev \
  libssl-dev \
  make \
  zlib1g-dev

# Use flags -LJO to follow the html redirect and download .tar.gz.
WORKDIR /root
RUN curl -LJO https://github.com/python/cpython/archive/v${LANG_VER}.tar.gz
RUN tar -zxf cpython-${LANG_VER}.tar.gz

WORKDIR ${LANG_DIR}
RUN ./configure --with-pydebug
RUN make -s -j2

COPY --from=golang /proctor /proctor
ENTRYPOINT ["/proctor"]
