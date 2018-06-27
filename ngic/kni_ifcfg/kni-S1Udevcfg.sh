#! /bin/bash
source ../config/dp_config.cfg
ifconfig $UL_IFACE
ifconfig $UL_IFACE $S1U_IP/24
ifconfig $UL_IFACE

