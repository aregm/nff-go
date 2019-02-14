# Copyright 2019 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
include $(PATH_TO_MK)/include.mk

.PHONY: testing
testing: check-pktgen
	go test

.PHONY: coverage
coverage:
	go test -cover -coverprofile=c.out
	go tool cover -html=c.out -o common_coverage.html
