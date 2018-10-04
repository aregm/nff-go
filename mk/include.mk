# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

.DEFAULT_GOAL := all

PROJECT_ROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/..)

DPDK_VERSION = 18.08
DPDK_DIR = dpdk-$(DPDK_VERSION)
ifndef DPDK_URL
DPDK_URL=http://fast.dpdk.org/rel/dpdk-$(DPDK_VERSION).tar.xz
endif
PKTGEN_VERSION=3.5.2
PKTGEN_DIR=pktgen-dpdk-pktgen-$(PKTGEN_VERSION)
ifndef PKTGEN_URL
PKTGEN_URL=http://git.dpdk.org/apps/pktgen-dpdk/snapshot/pktgen-dpdk-pktgen-$(PKTGEN_VERSION).tar.xz
endif
export RTE_SDK = $(PROJECT_ROOT)/dpdk/$(DPDK_DIR)
export RTE_TARGET = x86_64-native-linuxapp-gcc

# Configure flags for native code. Disable FSGSBASE and F16C to run in
# VMs and Docker containers.
CFLAGS = -I$(RTE_SDK)/$(RTE_TARGET)/include	\
	-O3					\
	-std=gnu11				\
	-m64					\
	-pthread				\
	-march=native				\
	-mno-fsgsbase                           \
	-mno-f16c                               \
	-DRTE_MACHINE_CPUFLAG_SSE		\
	-DRTE_MACHINE_CPUFLAG_SSE2		\
	-DRTE_MACHINE_CPUFLAG_SSE3		\
	-DRTE_MACHINE_CPUFLAG_SSSE3		\
	-DRTE_MACHINE_CPUFLAG_SSE4_1		\
	-DRTE_MACHINE_CPUFLAG_SSE4_2		\
	-DRTE_MACHINE_CPUFLAG_PCLMULQDQ		\
	-DRTE_MACHINE_CPUFLAG_RDRAND		\
	-DRTE_MACHINE_CPUFLAG_F16C		\
	-include rte_config.h			\
	-Wno-deprecated-declarations

ifdef NFF_GO_DEBUG
export CFLAGS += -g -O0 -D DEBUG
endif

HAVE_AVX2 := $(shell grep avx2 /proc/cpuinfo)
ifdef HAVE_AVX2
$(info Checking for AVX support... AVX and AVX2)
CFLAGS += -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_AVX2
else
HAVE_AVX := $(shell grep avx /proc/cpuinfo)
ifdef HAVE_AVX
$(info Checking for AVX support... AVX)
CFLAGS += -DRTE_MACHINE_CPUFLAG_AVX
else
$(info Checking for AVX support... no)
endif
endif

export CGO_CFLAGS = $(CFLAGS)

export CGO_LDFLAGS =				\
	-L$(RTE_SDK)/$(RTE_TARGET)/lib 		\
	-Wl,--no-as-needed			\
	-Wl,-export-dynamic

export CGO_LDFLAGS_ALLOW=-Wl,--((no-)?whole-archive|((start|end)-group))

# Universal check whether a variable is set
.PHONY: .check-defined-%
.check-defined-%:
	@if [ -z '${${*}}' ]; then echo "!!! Variable $* is undefined" && exit 1; fi

check-pktgen:
	@if [ ! -f $(PROJECT_ROOT)/dpdk/pktgen ]; then						\
		echo "!!! It is necessary to build DPDK before building any parts of NFF-GO." &&	\
		echo "!!! Please run make at the project root or in dpdk subdirectory" &&	\
		exit 1;										\
	fi
