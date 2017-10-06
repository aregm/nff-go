# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

FROM yanff-base

LABEL RUN docker run -it --privileged -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v /sys/devices/system/node:/sys/devices/system/node -v /dev:/dev --name NAME -e NAME=NAME -e IMAGE=IMAGE IMAGE"

WORKDIR /workdir

COPY step1 .
COPY step2 .
COPY step3 .
COPY step4 .
COPY step5 .
COPY step6 .
COPY step7 .
COPY step8 .
COPY step9 .
COPY step10 .
COPY step11 .
COPY rules1.conf .
COPY rules2.conf .
