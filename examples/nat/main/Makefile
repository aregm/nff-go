# Copyright 2017-2018 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../../../mk
IMAGENAME = nff-go-nat
EXECUTABLES = nat

nat: ../config.go ../translation.go ../portalloc.go ../cksum.go ../util.go ../arp.go ../icmp.go ../grpc.go ../dhcp.go ../neigh.go ../updatecfg/updatecfg.pb.go

../updatecfg/updatecfg.pb.go: ../updatecfg/updatecfg.proto
	protoc -I ../updatecfg --go_out=plugins=grpc:../updatecfg ../updatecfg/updatecfg.proto

include $(PATH_TO_MK)/leaf.mk
