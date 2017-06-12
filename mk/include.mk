# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

.DEFAULT_GOAL := all

PROJECT_ROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/..)

DPDK_VERSION = 17.02.1
DPDK_DIR = dpdk-stable-$(DPDK_VERSION)
export RTE_SDK = $(PROJECT_ROOT)/test/dpdk/$(DPDK_DIR)
export RTE_TARGET = x86_64-native-linuxapp-gcc
export CGO_CFLAGS = -I$(RTE_SDK)/$(RTE_TARGET)/include
export CGO_LDFLAGS = -L$(RTE_SDK)/$(RTE_TARGET)/lib

# Universal check whether a variable is set
.PHONY: .check-defined-%
.check-defined-%:
	if [ -z '${${*}}' ]; then echo "Variable $* is undefined" && exit 1; fi
