# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
IMAGENAME = nff-go-examples
EXECUTABLES = dump clonablePcapDumper kni copy errorHandling \
			  createPacket sendFixedPktsNumber
SUBDIRS = nat tutorial antiddos demo fileReadWrite firewall forwarding

gopacket:
	go get -v github.com/google/gopacket

gopacketParserExample: gopacket
	go build gopacketParserExample.go

include $(PATH_TO_MK)/intermediate.mk
include $(PATH_TO_MK)/leaf.mk
