# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

.DEFAULT_GOAL := all

PROJECT_ROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/..)

# Main DPDK variables
DPDK_DIR=dpdk
PKTGEN_DIR=pktgen-dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc
DPDK_INSTALL_DIR=$(RTE_TARGET)-install
export RTE_SDK=$(PROJECT_ROOT)/dpdk/$(DPDK_DIR)/$(DPDK_INSTALL_DIR)/usr/local/share/dpdk

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

ifndef NFF_GO_NO_MLX_DRIVERS
ifeq (,$(findstring mlx,$(GO_BUILD_TAGS)))
export GO_BUILD_TAGS += mlx
endif
endif

ifndef NFF_GO_NO_BPF_SUPPORT
ifeq (,$(findstring bpf,$(GO_BUILD_TAGS)))
export GO_BUILD_TAGS += bpf
endif
CFLAGS += -DNFF_GO_SUPPORT_XDP
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
