# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = mk
SUBDIRS = dpdk test examples
DOC_TARGETS = flow rules packet
TESTING_TARGETS = packet rules

all: $(SUBDIRS)

.PHONY: testing
testing: $(TESTING_TARGETS)					\
	for dir in $(TESTING_TARGETS); do			\
		if ! $(MAKE) -C $$dir $@; then break; fi;	\
	done

.PHONY: doc
doc: $(DOC_TARGETS)
	mkdir doc
	$(foreach package,$(DOC_TARGETS),godoc -analysis=type -analysis=pointer -html github.com/intel-go/yanff/$(package) > doc/$(package).html;)

include $(PATH_TO_MK)/intermediate.mk
