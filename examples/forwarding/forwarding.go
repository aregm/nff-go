// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var l3Rules *packet.L3Rules

// Main function for constructing packet processing graph.
func main() {
	var err error
	// Initialize NFF-GO library at 16 cores by default
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.CheckFatal(flow.SystemInit(&config))

	// Get splitting rules from access control file.
	l3Rules, err = packet.GetL3ACLFromORIG("forwarding.conf")
	flow.CheckFatal(err)

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow, err := flow.SetReceiver(0)
	flow.CheckFatal(err)

	// Split packet flow based on ACL.
	flowsNumber := uint16(5)
	outputFlows, err := flow.SetSplitter(inputFlow, l3Splitter, uint(flowsNumber), nil)
	flow.CheckFatal(err)

	// "0" flow is used for dropping packets without sending them.
	flow.CheckFatal(flow.SetStopper(outputFlows[0]))

	// Send each flow to corresponding port. Send queues will be added automatically.
	for i := uint16(1); i < flowsNumber; i++ {
		flow.CheckFatal(flow.SetSender(outputFlows[i], i-1))
	}

	// Begin to process packets.
	flow.CheckFatal(flow.SystemStart())
}

// User defined function for splitting packets
func l3Splitter(currentPacket *packet.Packet, context flow.UserContext) uint {
	// Return number of flow to which put this packet. Based on ACL rules.
	return currentPacket.L3ACLPort(l3Rules)
}
