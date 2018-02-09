# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../../mk
SUBDIRS = main

main: apptype_string.go

%_string.go: types.go
	go generate

include $(PATH_TO_MK)/intermediate.mk
