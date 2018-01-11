# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = mk
SUBDIRS = yanff-base dpdk test examples
DOC_TARGETS = flow packet
TESTING_TARGETS = packet

all: $(SUBDIRS)

dpdk: yanff-base

test: dpdk

examples: dpdk

perf_testing:
	$(MAKE) -C test perf_testing

.PHONY: testing $(TESTING_TARGETS)
testing: $(TESTING_TARGETS)
$(TESTING_TARGETS):
	$(MAKE) -C $@ testing

.PHONY: doc
doc: $(DOC_TARGETS)
	mkdir doc
	$(foreach package,$(DOC_TARGETS),godoc -analysis=type -analysis=pointer -html github.com/intel-go/yanff/$(package) > doc/$(package).html;)

include $(PATH_TO_MK)/intermediate.mk
