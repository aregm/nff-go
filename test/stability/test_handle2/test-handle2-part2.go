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
	l3Rules *rules.L3Rules

	outport uint
	inport  uint
)

// Main function for constructing packet processing graph.
func main() {
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.Parse()

	// Init YANFF system at 16 available cores.
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.SystemInit(&config)

	// Get splitting rules from access control file.
	l3Rules = rules.GetL3RulesFromORIG("test-handle2-l3rules.conf")

	// Receive packets from 0 port
	flow1 := flow.SetReceiver(uint8(inport))

	// Handle packet flow
	flow.SetHandler(flow1, l3Handler, nil) // ~33% of packets should left in flow1

	// Send each flow to corresponding port. Send queues will be added automatically.
	flow.SetSender(flow1, uint8(outport))

	// Begin to process packets.
	flow.SystemStart()
}

func l3Handler(pkt *packet.Packet, context flow.UserContext) bool {
	return rules.L3ACLPermit(pkt, l3Rules)
}
