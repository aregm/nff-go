// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"github.com/intel-go/yanff/rules"
)

var L3Rules *rules.L3Rules
var options = `{"cores": {"Value": 8, "Locked": false}}`

// Main function for constructing packet processing graph.
func main() {
	// Initialize YANFF library at requested number of cores.
	flow.SystemInit(options)

	// Get filtering rules from access control file.
	L3Rules = rules.GetL3RulesFromORIG("Firewall.conf")

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow := flow.SetReceiver(0)

	// Separate packet flow based on ACL.
	rejectFlow := flow.SetSeparator(inputFlow, L3Separator)

	// Drop rejected packets.
	flow.SetStopper(rejectFlow)

	// Send accepted packets to first port. Send queue will be added automatically.
	flow.SetSender(inputFlow, 1)

	// Begin to process packets.
	flow.SystemStart()
}

// User defined function for separating packets
func L3Separator(currentPacket *packet.Packet) bool {
	// Firstly set up all fields at packet: MAC, IPv4 or IPv6, TCP or UDP.
	currentPacket.ParseL4()

	// Return whether packet is accepted or not. Based on ACL rules.
	return rules.L3_ACL_permit(currentPacket, L3Rules)
}
