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
	inport uint
)

func main() {
	hexdumpOn := flag.Bool("hex", false, "enable dumping of packets in hex format")
	flag.UintVar(&outport, "outport", 1, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")

	// Initialize YANFF library at 10 available cores
	flow.SystemInit(10)

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow := flow.SetReceiver(uint8(inport))

	// Separate each 50000000th packet for dumping
	secondFlow := flow.SetPartitioner(firstFlow, 50000000, 1)

	// Dump separated packet. By default function dumper() is used.
	if *hexdumpOn {
		flow.SetHandler(secondFlow, hexdumper, nil)
	} else {
		flow.SetHandler(secondFlow, dumper, nil)
	}

	// Merge packet to original flow
	output := flow.SetMerger(firstFlow, secondFlow)

	// Send packets to control speed. One queue will be added automatically.
	flow.SetSender(output, uint8(outport))

	flow.SystemStart()
}

func dumper(currentPacket *packet.Packet, context flow.UserContext) {
	currentPacket.ParseL4()
	fmt.Printf("%v", currentPacket.Ether)
	if currentPacket.IPv4 != nil {
		fmt.Printf("%v", currentPacket.IPv4)
	} else if currentPacket.IPv6 != nil {
		fmt.Printf("%v", currentPacket.IPv6)
	} else {
		fmt.Println("    Unknown L3 protocol")
	}
	if currentPacket.TCP != nil {
		fmt.Printf("%v", currentPacket.TCP)
	} else if currentPacket.UDP != nil {
		fmt.Printf("%v", currentPacket.UDP)
	} else {
		fmt.Println("        Unknown L4 protocol")
	}
	fmt.Println("----------------------------------------------------------")
}

func hexdumper(currentPacket *packet.Packet, context flow.UserContext) {
	fmt.Printf("Raw bytes=%x\n", currentPacket.GetRawPacketBytes())
}
