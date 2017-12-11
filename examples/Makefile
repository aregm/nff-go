# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
IMAGENAME = yanff-examples
EXECUTABLES = demo dump Forwarding Firewall clonable_pcap_dumper kni copy

all: nat tutorial antiddos

.PHONY: nat
nat:
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: tutorial
tutorial:
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: antiddos
antiddos:
	$(MAKE) -C $@ $(MAKECMDGOALS)

include $(PATH_TO_MK)/leaf.mk
