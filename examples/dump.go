// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var (
	outport uint
	inport  uint
)

func main() {
	dumptype := flag.Uint("dumptype", 0, "dumping format type (0 - dumper function, 1 - hex, 2 - pcap file)")
	flag.UintVar(&outport, "outport", 1, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.Parse()

	// Initialize YANFF library at 10 available cores
	config := flow.Config{
		CPUList: "0-9",
	}
	flow.SystemInit(&config)

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow := flow.SetReceiver(uint8(inport))

	// Separate each 50000000th packet for dumping
	secondFlow := flow.SetPartitioner(firstFlow, 50000000, 1)

	// Dump separated packet. By default function dumper() is used.
	switch *dumptype {
	case 1:
		flow.SetHandler(secondFlow, hexdumper, nil)
	case 2:
		// Writer closes flow
		flow.SetSender(secondFlow, "out.pcap")
	default:
		flow.SetHandler(secondFlow, dumper, nil)
	}

	// All cases except writing to file require to merge partitioned packets to original flow
	var output *flow.Flow
	if *dumptype == 2 {
		output = firstFlow
	} else {
		output = flow.SetMerger(firstFlow, secondFlow)
	}
	flow.SetSender(output, uint8(outport))

	flow.SystemStart()
}

func dumper(currentPacket *packet.Packet, context flow.UserContext) {
	var tcp *packet.TCPHdr
	var udp *packet.UDPHdr
	var icmp *packet.ICMPHdr

	fmt.Printf("%v", currentPacket.Ether)
	ipv4, ipv6, arp := currentPacket.ParseAllKnownL3()
	if ipv4 != nil {
		fmt.Printf("%v", ipv4)
		tcp, udp, icmp = currentPacket.ParseAllKnownL4ForIPv4()
	} else if ipv6 != nil {
		fmt.Printf("%v", ipv6)
		tcp, udp, icmp = currentPacket.ParseAllKnownL4ForIPv6()
	} else if arp != nil {
		fmt.Printf("%v", arp)
	} else {
		fmt.Println("    Unknown L3 protocol")
	}

	if tcp != nil {
		fmt.Printf("%v", tcp)
	} else if udp != nil {
		fmt.Printf("%v", udp)
	} else if icmp != nil {
		fmt.Printf("%v", icmp)
	} else {
		fmt.Println("        Unknown L4 protocol")
	}
	fmt.Println("----------------------------------------------------------")
}

func hexdumper(currentPacket *packet.Packet, context flow.UserContext) {
	fmt.Printf("Raw bytes=%x\n", currentPacket.GetRawPacketBytes())
}
