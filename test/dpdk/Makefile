# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../../mk
IMAGENAME = nfv-pktgen

include $(PATH_TO_MK)/leaf.mk

# Main DPDK variables
DEST_DPDK_DIR=$(RTE_TARGET)-install
export WORKDIR=/workdir

# Pktgen variables
PKTGEN_VERSION=3.1.0
PKTGEN_DIR=pktgen-v$(PKTGEN_VERSION)

.PHONY: build-dpdk
all: build-dpdk pktgen Pktgen.lua

$(DPDK_DIR):
	curl http://fast.dpdk.org/rel/dpdk-$(DPDK_VERSION).tar.xz | tar xJ
	cd $(DPDK_DIR) && patch -p0 < ../DPDK_17_02.patch

$(DPDK_DIR)/$(DPDK_INSTALL_DIR): $(DPDK_DIR)
	make -C $(DPDK_DIR) config T=$(RTE_TARGET)
	make -C $(DPDK_DIR) install T=$(RTE_TARGET) DESTDIR=$(DPDK_INSTALL_DIR)

build-dpdk: $(DPDK_DIR)/$(DPDK_INSTALL_DIR)

$(PKTGEN_DIR):
	curl http://dpdk.org/browse/apps/pktgen-dpdk/snapshot/pktgen-v$(PKTGEN_VERSION).tar.xz | tar xJ

$(PKTGEN_DIR)/app/app/$(RTE_TARGET)/pktgen: build-dpdk $(PKTGEN_DIR)
	make -C $(PKTGEN_DIR)

pktgen: $(PKTGEN_DIR)/app/app/$(RTE_TARGET)/pktgen
	cp $(PKTGEN_DIR)/app/app/$(RTE_TARGET)/pktgen .

Pktgen.lua: $(PKTGEN_DIR)/app/app/$(RTE_TARGET)/pktgen
	cp $(PKTGEN_DIR)/Pktgen.lua .

vars.sh: build-dpdk
	echo export RTE_SDK=$(WORKDIR)/dpdk-$(DPDK_VERSION) > vars.sh
	echo export RTE_TARGET=$(RTE_TARGET) >> vars.sh

clean:
	-rm pktgen Pktgen.lua
	-rm -rf $(DPDK_DIR)
	-rm -rf $(PKTGEN_DIR)
