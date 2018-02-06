# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../../mk
SUBDIRS = test_resend test_merge test_split test_separate test_partition test_handle2 test_cksum

testing:
	for dir in $(SUBDIRS); do \
		cd $$dir && make testing; cd -; \
	done

include $(PATH_TO_MK)/intermediate.mk
