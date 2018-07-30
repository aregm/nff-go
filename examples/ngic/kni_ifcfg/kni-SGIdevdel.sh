#! /bin/bash
source ../config/dp_config.cfg
ifconfig $SGIDeviceName
ip addr del $SGI_IP/24 dev $SGIDeviceName
ifconfig $SGIDeviceName

