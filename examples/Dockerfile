# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

ARG USER_NAME
FROM ${USER_NAME}/nff-go-base

LABEL RUN docker run -it --privileged -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v /sys/devices/system/node:/sys/devices/system/node -v /dev:/dev --name NAME -e NAME=NAME -e IMAGE=IMAGE IMAGE

WORKDIR /workdir
COPY demo .
COPY demoL2_ACL.json .
COPY demoL3_ACL.json .
COPY dump .
COPY Firewall .
COPY Firewall.conf .
COPY Forwarding .
COPY Forwarding.conf .
COPY clonable_pcap_dumper .
COPY kni .
COPY copy .

CMD ["./demo"]
