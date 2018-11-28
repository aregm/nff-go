FROM ubuntu:cosmic

ARG MAKEFLAGS=-j2

ENV GOROOT /opt/go
ENV PATH ${GOROOT}/bin:${GOPATH}/bin:${PATH}
ENV NFF_GO /nff-go

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
    libhyperscan-dev \
    liblua5.3-dev

RUN cd /opt && curl -L -s https://dl.google.com/go/go1.11.2.linux-amd64.tar.gz | tar zx

RUN mkdir -p ${NFF_GO}
COPY . ${NFF_GO}

WORKDIR ${NFF_GO}
