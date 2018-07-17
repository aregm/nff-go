#! /bin/bash
source ../config/dp_config.cfg
ifconfig $DL_IFACE
ip addr del $SGI_IP/24 dev $DL_IFACE
ifconfig $DL_IFACE

