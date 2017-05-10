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
	// Init YANFF system at requested number of cores.
	flow.SystemInit(options)

	// Get splitting rules from access control file.
	L3Rules = rules.GetL3RulesFromORIG("test-split.conf")

	// Receive packets from 0 port
	inputFlow := flow.SetReceiver(0)

	// Split packet flow based on ACL.
	flowsNumber := 4
	outputFlows := flow.SetSplitter(inputFlow, L3Splitter, uint(flowsNumber))

	// "0" flow is used for dropping packets without sending them.
	flow.SetStopper(outputFlows[0])

	// Send each flow to corresponding port. Send queues will be added automatically.
	flow.SetSender(outputFlows[1], 1)
	flow.SetSender(outputFlows[2], 2)
	flow.SetSender(outputFlows[3], 3)

	// Begin to process packets.
	flow.SystemStart()
}

func L3Splitter(currentPacket *packet.Packet) uint {
	// Firstly set up all fields at packet: MAC, IPv4 or IPv6, TCP or UDP.
	currentPacket.ParseL4()

	// Return number of flow to which put this packet. Based on ACL rules.
	return rules.L3_ACL_port(currentPacket, L3Rules)
}
