#! /bin/bash
source ../config/dp_config.cfg
ifconfig $SGIDeviceName
ifconfig $SGIDeviceName $SGI_IP/24
ifconfig $SGIDeviceName

