# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
SUBDIRS = stability performance stash

apptype_string.go:
	go generate

main: apptype_string.go

include $(PATH_TO_MK)/intermediate.mk
