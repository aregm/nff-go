# Copyright 2017 Intel Corporation. 
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

FROM nfvbase

LABEL RUN docker run -it --privileged -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v /sys/devices/system/node:/sys/devices/system/node -v /dev:/dev --name NAME -e NAME=NAME -e IMAGE=IMAGE IMAGE"

EXPOSE 22022

WORKDIR /workdir
COPY pktgen .
COPY Pktgen.lua .

CMD ["./pktgen", "-c", "0x1ff", "-n", "4", "--", "-P", "-m", "[1:1-2].0, [3:3-4].1, [5-6:5].2, [7-8:7].3", "-G"]
