# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
IMAGENAME = nff-go-examples
EXECUTABLES = demo dump Forwarding Firewall clonable_pcap_dumper kni copy ErrorHandling
SUBDIRS = nat tutorial antiddos

gopacket:
	go get -v github.com/google/gopacket

gopacket_parser_example: gopacket
	go build gopacket_parser_example.go

include $(PATH_TO_MK)/intermediate.mk
include $(PATH_TO_MK)/leaf.mk
