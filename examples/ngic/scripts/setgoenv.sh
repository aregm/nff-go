#! /bin/bash

# it will be replaced by install_nffgo.sh and will sync the DPDK version
DPDK_VERSION=18.02

if [[ ! -v GOROOT ]]; then 
    export GOROOT=$PWD/go
fi

export GOPATH=$PWD/nff
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin

unset RTE_SDK
unset RTE_TARGET
RTE_SDK=$PWD/nff/src/github.com/intel-go/nff-go/dpdk/dpdk-$DPDK_VERSION
export RTE_SDK=$RTE_SDK
export RTE_TARGET=x86_64-native-linuxapp-gcc
pushd $GOPATH/src/github.com/intel-go/nff-go

