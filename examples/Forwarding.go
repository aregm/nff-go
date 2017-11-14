// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"github.com/intel-go/yanff/rules"
)

var l3Rules *rules.L3Rules

// Main function for constructing packet processing graph.
func main() {
	// Initialize YANFF library at 16 cores by default
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.SystemInit(&config)

	// Get splitting rules from access control file.
	l3Rules = rules.GetL3RulesFromORIG("Forwarding.conf")

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow := flow.SetReceiver(0)

	// Split packet flow based on ACL.
	flowsNumber := 5
	outputFlows := flow.SetSplitter(inputFlow, l3Splitter, uint(flowsNumber), nil)

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
func l3Splitter(currentPacket *packet.Packet, context flow.UserContext) uint {
	// Return number of flow to which put this packet. Based on ACL rules.
	return rules.L3ACLPort(currentPacket, l3Rules)
}
