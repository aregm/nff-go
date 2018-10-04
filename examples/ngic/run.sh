#!/bin/bash

source config/dp_config.cfg

#DEBUG=true
DEBUG=false
FLOW_DEBUG=false

echo "" > log/dp.log

./ngicdp  -kni=$NeedKNI \
	   -debug=$DEBUG \
	   -flow_debug=$FLOW_DEBUG \
	   -cpu_list $CPUList \
	   -memory $MEMORY \
	   -s1u_port $S1U_PORT_IDX \
	   -sgi_port $SGI_PORT_IDX \
	   -s1u_ip $S1U_IP \
	   -sgi_ip $SGI_IP \
	   -s1u_dev $S1UDeviceName \
	   -sgi_dev $SGIDeviceName


