# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

ARG USER_NAME
FROM ${USER_NAME}/nff-go-base

LABEL RUN docker run -it --privileged -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v /sys/devices/system/node:/sys/devices/system/node -v /dev:/dev --name NAME -e NAME=NAME -e IMAGE=IMAGE IMAGE

WORKDIR /workdir
COPY testSingleWorkingFF .
COPY test-separate-l3rules.conf .
COPY test-split.conf .
COPY test-handle-l3rules.conf .
COPY config.json .
