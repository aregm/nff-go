# Copyright 2017-2019 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
IMAGENAME = nff-go-pktgen

# Pktgen variables
NOCHECK_PKTGEN = yes

include $(PATH_TO_MK)/leaf.mk

# Disable FSGSBASE and F16C to run in VMs and Docker containers.
export EXTRA_CFLAGS = -mno-fsgsbase -mno-f16c
ifdef NFF_GO_DEBUG
export EXTRA_CFLAGS += -g -O0
endif

.PHONY: dpdk
dpdk: all

all: pktgen

$(DPDK_DIR)/$(DPDK_INSTALL_DIR):
	$(MAKE) -C $(DPDK_DIR) config T=$(RTE_TARGET)
	@if [ -z '${NFF_GO_NO_MLX_DRIVERS}' ]; then				\
		echo BUILDING DPDK WITH MLX DRIVERS;				\
		sed -ri 's,(MLX._PMD=)n,\1y,' $(DPDK_DIR)/build/.config;	\
	else									\
		echo BUILDING DPDK WITHOUT MLX DRIVERS;				\
	fi
	$(MAKE) -C $(DPDK_DIR)
	$(MAKE) -C $(DPDK_DIR) install DESTDIR=$(DPDK_INSTALL_DIR)

$(PKTGEN_DIR)/app/$(RTE_TARGET)/pktgen: $(DPDK_DIR)/$(DPDK_INSTALL_DIR)
	$(MAKE) -C $(PKTGEN_DIR)

pktgen: $(PKTGEN_DIR)/app/$(RTE_TARGET)/pktgen
	cp $(PKTGEN_DIR)/app/$(RTE_TARGET)/pktgen .

clean:
	-$(MAKE) -C $(PKTGEN_DIR) realclean
	-rm pktgen
	-$(MAKE) -C $(DPDK_DIR) clean
	-rm -rf $(DPDK_DIR)/$(DPDK_INSTALL_DIR) $(DPDK_DIR)/build
