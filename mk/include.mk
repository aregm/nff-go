# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

.DEFAULT_GOAL := all

PROJECT_ROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/..)

DPDK_VERSION = 17.02.1
DPDK_DIR = dpdk-stable-$(DPDK_VERSION)
export RTE_SDK = $(PROJECT_ROOT)/dpdk/$(DPDK_DIR)
export RTE_TARGET = x86_64-native-linuxapp-gcc

# Configure flags for native code
CFLAGS = -I$(RTE_SDK)/$(RTE_TARGET)/include	\
	-O3					\
	-g					\
	-std=gnu11				\
	-m64					\
	-pthread				\
	-march=native				\
	-DRTE_MACHINE_CPUFLAG_SSE		\
	-DRTE_MACHINE_CPUFLAG_SSE2		\
	-DRTE_MACHINE_CPUFLAG_SSE3		\
	-DRTE_MACHINE_CPUFLAG_SSSE3		\
	-DRTE_MACHINE_CPUFLAG_SSE4_1		\
	-DRTE_MACHINE_CPUFLAG_SSE4_2		\
	-DRTE_MACHINE_CPUFLAG_PCLMULQDQ		\
	-DRTE_MACHINE_CPUFLAG_RDRAND		\
	-DRTE_MACHINE_CPUFLAG_FSGSBASE		\
	-DRTE_MACHINE_CPUFLAG_F16C		\
	-include rte_config.h

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
# DEBUG flags
# export CGO_CFLAGS = -g -O0 -I$(RTE_SDK)/$(RTE_TARGET)/include

export CGO_LDFLAGS =				\
	-L$(RTE_SDK)/$(RTE_TARGET)/lib		\
	-W					\
	-Wall					\
	-Werror					\
	-Wstrict-prototypes			\
	-Wmissing-prototypes			\
	-Wmissing-declarations			\
	-Wold-style-definition			\
	-Wpointer-arith				\
	-Wcast-align				\
	-Wnested-externs			\
	-Wcast-qual				\
	-Wformat-nonliteral			\
	-Wformat-security			\
	-Wundef					\
	-Wwrite-strings				\
	-Wl,--no-as-needed			\
	-Wl,-export-dynamic			\
	-Wl,--whole-archive			\
	-lrte_distributor			\
	-lrte_reorder				\
	-lrte_kni				\
	-lrte_pipeline				\
	-lrte_table				\
	-lrte_port				\
	-lrte_timer				\
	-lrte_hash				\
	-lrte_jobstats				\
	-lrte_lpm				\
	-lrte_power				\
	-lrte_acl				\
	-lrte_meter				\
	-lrte_sched				\
	-lrte_vhost				\
	-Wl,--start-group			\
	-lrte_kvargs				\
	-lrte_mbuf				\
	-lrte_ip_frag				\
	-lrte_ethdev				\
	-lrte_mempool				\
	-lrte_ring				\
	-lrte_eal				\
	-lrte_cmdline				\
	-lrte_cfgfile				\
	-lrte_pmd_bond				\
	-lrte_pmd_vmxnet3_uio			\
	-lrte_net				\
	-lrte_pmd_virtio			\
	-lrte_pmd_cxgbe				\
	-lrte_pmd_enic				\
	-lrte_pmd_i40e				\
	-lrte_pmd_fm10k				\
	-lrte_pmd_ixgbe				\
	-lrte_pmd_e1000				\
	-lrte_pmd_ring				\
	-lrte_pmd_af_packet			\
	-lrte_pmd_null				\
	-lrt					\
	-lm					\
	-ldl					\
	-Wl,--end-group				\
	-Wl,--no-whole-archive

# Universal check whether a variable is set
.PHONY: .check-defined-%
.check-defined-%:
	@if [ -z '${${*}}' ]; then echo "!!! Variable $* is undefined" && exit 1; fi

check-pktgen:
	@if [ ! -f $(PROJECT_ROOT)/dpdk/pktgen ]; then						\
		echo "!!! It is necessary to build DPDK before building any parts of YANFF." &&	\
		echo "!!! Please run make at the project root or in dpdk subdirectory" &&	\
		exit 1;										\
	fi
