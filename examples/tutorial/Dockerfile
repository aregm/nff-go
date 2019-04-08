# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

ARG USER_NAME
FROM ${USER_NAME}/nff-go-base

LABEL RUN docker run -it --privileged -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v /sys/devices/system/node:/sys/devices/system/node -v /dev:/dev --name NAME -e NAME=NAME -e IMAGE=IMAGE IMAGE

WORKDIR /workdir

COPY step01 .
COPY step02 .
COPY step03 .
COPY step04 .
COPY step05 .
COPY step06 .
COPY step07 .
COPY step08 .
COPY step09 .
COPY step10 .
COPY step11 .
COPY rules1.conf .
COPY rules2.conf .
