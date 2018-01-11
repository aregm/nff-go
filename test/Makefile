# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
SUBDIRS = stability performance stash
.PHONY: main perf_testing

perf_testing: main
	$(MAKE) -C ./main perf_testing

main: apptype_string.go
	$(MAKE) -C ./main main

apptype_string.go:
	go generate

include $(PATH_TO_MK)/intermediate.mk
