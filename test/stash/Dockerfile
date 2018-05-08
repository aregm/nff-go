# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

ARG USER_NAME
FROM ${USER_NAME}/nff-go-base

LABEL RUN docker run -it --privileged -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v /sys/devices/system/node:/sys/devices/system/node -v /dev:/dev --name NAME -e NAME=NAME -e IMAGE=IMAGE IMAGE

WORKDIR /workdir
COPY forwardingTestL3 .
COPY forwardingTestL3_ACL.conf .
COPY forwardingTestL3_ACL.json .
COPY sendback .
COPY sendback.json .
COPY linuxReorderTestReceive.go .
COPY linuxReorderTestSend.go .
