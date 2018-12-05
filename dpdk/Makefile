# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
IMAGENAME = nff-go-pktgen

# Pktgen variables
NOCHECK_PKTGEN = yes

# Main DPDK variables
DPDK_INSTALL_DIR=$(RTE_TARGET)-install
export WORKDIR=/workdir

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
	$(MAKE) -C $(DPDK_DIR) install T=$(RTE_TARGET) DESTDIR=$(DPDK_INSTALL_DIR)

$(PKTGEN_DIR)/app/$(RTE_TARGET)/pktgen: $(DPDK_DIR)/$(DPDK_INSTALL_DIR)
	$(MAKE) -C $(PKTGEN_DIR)

pktgen: $(PKTGEN_DIR)/app/$(RTE_TARGET)/pktgen
	cp $(PKTGEN_DIR)/app/$(RTE_TARGET)/pktgen .

clean:
	-$(MAKE) -C $(DPDK_DIR) clean
	-rm -rf $(DPDK_DIR)/$(DPDK_INSTALL_DIR) $(DPDK_DIR)/build $(DPDK_DIR)/$(RTE_TARGET)
	-$(MAKE) -C $(PKTGEN_DIR) realclean

include $(PATH_TO_MK)/leaf.mk
