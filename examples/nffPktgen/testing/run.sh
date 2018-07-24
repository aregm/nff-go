#!/bin/bash

./../generate -number 100000 -infile ether.json -outfile ether.pcap
./../generate -number 10000 -infile ip4.json -outfile ip4.pcap
./../generate -number 1000 -infile ip6.json -outfile ip6.pcap
./../generate -number 100000 -infile ip4tcp.json -outfile ip4tcp.pcap
./../generate -number 1000000 -infile ip6tcp.json -outfile ip6tcp.pcap
./../generate -number 10000 -infile ip4udp.json -outfile ip4udp.pcap
./../generate -number 1000 -infile ip6udp.json -outfile ip6udp.pcap
./../generate -number 1000000 -infile ip4icmp.json -outfile ip4icmp.pcap
./../generate -number 100000 -infile ip6icmp.json -outfile ip6icmp.pcap
./../generate -number 1000 -infile arp.json -outfile arp.pcap
./../generate -number 10 -infile vlanTag.json -outfile vlanTag.pcap
./../generate -number 10 -infile arpVlan.json -outfile arpVlan.pcap
./../generate -number 100