# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../../mk
SUBDIRS = testMerge testSingleWorkingFF testCksum

include $(PATH_TO_MK)/intermediate.mk

testing:
	for dir in $(SUBDIRS); do \
		cd $$dir && make testing; cd -; \
	done
