#! /bin/bash
source ../config/dp_config.cfg
ifconfig $S1UDeviceName
ifconfig $S1UDeviceName $S1U_IP/24
ifconfig $S1UDeviceName

