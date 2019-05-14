# Copyright 2018 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../../../mk
IMAGENAME = dpi
EXECUTABLES = dpi

dpi: ../pattern gohs

gohs:
	go get -tags hyperscan_v4 -v github.com/flier/gohs/hyperscan

COMMON_FILES = handlers.go

include $(PATH_TO_MK)/leaf.mk
