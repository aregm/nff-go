# Copyright 2018 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../../../mk
EXECUTABLES = client

nat: client.go ../updatecfg/updatecfg.pb.go

../updatecfg/updatecfg.pb.go: ../updatecfg/updatecfg.proto
	protoc -I ../updatecfg --go_out=plugins=grpc:../updatecfg ../updatecfg/updatecfg.proto

include $(PATH_TO_MK)/leaf.mk
