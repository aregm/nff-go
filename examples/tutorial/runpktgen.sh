#!/bin/bash

cd ../../dpdk
sudo ./pktgen -c 0xff -n 4 -- -P -m "[1:2].0, [3:4].1" -T
rc=$?; if [[ $rc == 0 ]]; then reset; fi
