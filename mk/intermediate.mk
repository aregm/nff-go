# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(PATH_TO_MK)/include.mk

TARGETS = all clean images clean-images deploy cleanall
.PHONY: $(TARGETS)

$(TARGETS):
	for dir in $(SUBDIRS); do				\
		if ! $(MAKE) -C $$dir $@; then break; fi;	\
	done
