#!/bin/bash -x

source config/dp_config.cfg

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
	   -sgi_dev $SGIDeviceName \
       -sarp=$STATIC_ARP \
       -simucp=$SIMULATE_CP \
       -pcap=$ENABLE_PCAP
