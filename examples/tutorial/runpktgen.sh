#!/bin/bash

cd ../../dpdk
sudo ./pktgen -c 0xffffffff -n 4 -- -P -m "[1-2:3-4].0, [5-6:7-8].1" -T
rc=$?; if [[ $rc == 0 ]]; then reset; fi
