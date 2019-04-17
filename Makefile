# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = mk
SUBDIRS = nff-go-base dpdk test examples
CI_TESTING_TARGETS = packet internal/low common
TESTING_TARGETS = $(CI_TESTING_TARGETS) test/stability

all: $(SUBDIRS)

debug:
	$(MAKE) all NFF_GO_DEBUG=y

dpdk: nff-go-base

test: dpdk

examples: dpdk

perf_testing:
	$(MAKE) -C test perf_testing

.PHONY: testing $(TESTING_TARGETS)
.NOTPARALLEL: testing $(TESTING_TARGETS)
testing: $(TESTING_TARGETS)

.PHONY: citesting $(CI_TESTING_TARGETS)
.NOTPARALLEL: citesting $(CI_TESTING_TARGETS)
citesting: $(CI_TESTING_TARGETS)

$(TESTING_TARGETS):
	$(MAKE) -C $@ testing

include $(PATH_TO_MK)/intermediate.mk
