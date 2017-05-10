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
var options = `{"cores": {"Value": 16, "Locked": false}}`

// Main function for constructing packet processing graph.
func main() {
	// Initialize YANFF library at requested number of cores.
	flow.SystemInit(options)

	// Get splitting rules from access control file.
	L3Rules = rules.GetL3RulesFromORIG("Forwarding.conf")

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow := flow.SetReceiver(0)

	// Split packet flow based on ACL.
	flowsNumber := 5
	outputFlows := flow.SetSplitter(inputFlow, L3Splitter, uint(flowsNumber))

	// "0" flow is used for dropping packets without sending them.
	flow.SetStopper(outputFlows[0])

	// Send each flow to corresponding port. Send queues will be added automatically.
	for i := 1; i < flowsNumber; i++ {
		flow.SetSender(outputFlows[i], uint8(i-1))
	}

	// Begin to process packets.
	flow.SystemStart()
}

// User defined function for splitting packets
func L3Splitter(currentPacket *packet.Packet) uint {
	// Firstly set up all fields at packet: MAC, IPv4 or IPv6, TCP or UDP.
	currentPacket.ParseL4()

	// Return number of flow to which put this packet. Based on ACL rules.
	return rules.L3_ACL_port(currentPacket, L3Rules)
}
