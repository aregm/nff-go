# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

.DEFAULT_GOAL := all

PROJECT_ROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/..)

DPDK_VERSION = 17.02.1
DPDK_DIR = dpdk-stable-$(DPDK_VERSION)
export RTE_SDK = $(PROJECT_ROOT)/dpdk/$(DPDK_DIR)
export RTE_TARGET = x86_64-native-linuxapp-gcc
export CGO_CFLAGS = -I$(RTE_SDK)/$(RTE_TARGET)/include
export CGO_LDFLAGS = -L$(RTE_SDK)/$(RTE_TARGET)/lib

# Universal check whether a variable is set
.PHONY: .check-defined-%
.check-defined-%:
	if [ -z '${${*}}' ]; then echo "Variable $* is undefined" && exit 1; fi

check-pktgen:
	if [ ! -f $(PROJECT_ROOT)/dpdk/pktgen ]; then						\
		echo "It is necessary to build DPDK before building any parts of YANFF." &&	\
		echo "Please run make at the project root or in dpdk subdirectory" &&		\
		exit 1;										\
	fi
