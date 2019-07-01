# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

TARGETS = all clean images clean-images deploy cleanall
.PHONY: $(TARGETS) $(SUBDIRS)

$(TARGETS): $(SUBDIRS)

included_from_dir := $(shell basename $(dir $(abspath $(word 1, $(MAKEFILE_LIST)))))
@eval $(included_from_dir): all

targets_to_execute := $(filter-out $(included_from_dir), $(MAKECMDGOALS))

$(SUBDIRS):
	$(MAKE) -C $@ $(targets_to_execute)
