#! /bin/bash
source ../config/dp_config.cfg
ifconfig $S1UDeviceName
ip addr del $S1U_IP/24 dev $S1UDeviceName
ifconfig $S1UDeviceName

