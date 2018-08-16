#! /bin/bash
# Copyright (c) 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# commented if go is already installed
export GOROOT=/opt/go
export GOPATH=$PWD/nff
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin

unset RTE_SDK
unset RTE_TARGET
RTE_SDK=$PWD/nff/src/github.com/intel-go/nff-go/dpdk/dpdk-18.02
export RTE_SDK=$RTE_SDK
export RTE_TARGET=x86_64-native-linuxapp-gcc
pushd $GOPATH/src/github.com/intel-go/nff-go

