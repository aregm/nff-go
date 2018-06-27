#! /bin/bash
source ../config/dp_config.cfg
ifconfig $DL_IFACE
ifconfig $DL_IFACE $SGI_IP/24
ifconfig $DL_IFACE

