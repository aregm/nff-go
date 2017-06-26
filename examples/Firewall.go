// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"github.com/intel-go/yanff/rules"
)

var (
	L3Rules   *rules.L3Rules
	outport uint
	inport uint
)

// Main function for constructing packet processing graph.
func main() {
	flag.UintVar(&outport, "outport", 1, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")

	// Initialize YANFF library at 8 cores by default
	flow.SystemInit(8)

	// Get filtering rules from access control file.
	L3Rules = rules.GetL3RulesFromORIG("Firewall.conf")

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow := flow.SetReceiver(uint8(inport))

	// Separate packet flow based on ACL.
	rejectFlow := flow.SetSeparator(inputFlow, L3Separator, nil)

	// Drop rejected packets.
	flow.SetStopper(rejectFlow)

	// Send accepted packets to first port. Send queue will be added automatically.
	flow.SetSender(inputFlow, uint8(outport))

	// Begin to process packets.
	flow.SystemStart()
}

// User defined function for separating packets
func L3Separator(currentPacket *packet.Packet, context flow.UserContext) bool {
	// Firstly set up all fields at packet: MAC, IPv4 or IPv6, TCP or UDP.
	currentPacket.ParseL4()

	// Return whether packet is accepted or not. Based on ACL rules.
	return rules.L3_ACL_permit(currentPacket, L3Rules)
}
