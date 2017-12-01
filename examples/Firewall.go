// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var (
	l3Rules *packet.L3Rules
	outport uint
	inport  uint
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

// Main function for constructing packet processing graph.
func main() {
	var err error
	flag.UintVar(&outport, "outport", 1, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.Parse()

	// Initialize YANFF library at 8 cores by default
	config := flow.Config{
		CPUList: "0-7",
	}
	CheckFatal(flow.SystemInit(&config))

	// Get filtering rules from access control file.
	l3Rules, err = packet.GetL3ACLFromORIG("Firewall.conf")
	CheckFatal(err)

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)

	// Separate packet flow based on ACL.
	rejectFlow, err := flow.SetSeparator(inputFlow, l3Separator, nil)
	CheckFatal(err)

	// Drop rejected packets.
	CheckFatal(flow.SetStopper(rejectFlow))

	// Send accepted packets to first port. Send queue will be added automatically.
	CheckFatal(flow.SetSender(inputFlow, uint8(outport)))

	// Begin to process packets.
	CheckFatal(flow.SystemStart())
}

// User defined function for separating packets
func l3Separator(currentPacket *packet.Packet, context flow.UserContext) bool {
	// Return whether packet is accepted or not. Based on ACL rules.
	return currentPacket.L3ACLPermit(l3Rules)
}
