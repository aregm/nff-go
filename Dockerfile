FROM ubuntu:bionic

ENV GO_VERSION 1.9
ENV GOPATH /gopath
ENV GOROOT /usr/lib/go-${GO_VERSION}

ENV PATH ${GOROOT}/bin:${GOPATH}/bin:${PATH}
ENV NFF_GO_DIR /gopath/src/github.com/intel-go/nff-go

ARG MAKEFLAGS=-j2

RUN apt-get -q update && apt-get -q -y install \
    make \
    git \
    curl \
    wget \
    golang-${GO_VERSION} \
    libpcap-dev \
    libelf-dev \
    hugepages  \
    libnuma-dev \
    libhyperscan-dev

RUN mkdir -p ${NFF_GO_DIR}
COPY . ${NFF_GO_DIR}

WORKDIR ${NFF_GO_DIR}
