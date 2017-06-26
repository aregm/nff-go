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
	L3Rules *rules.L3Rules

	inport  uint
	outport1 uint
	outport2 uint
)

// Main function for constructing packet processing graph.
func main() {
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.UintVar(&outport1, "outport1", 0, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")

	// Init YANFF system at 16 available cores.
	flow.SystemInit(16)

	// Get splitting rules from access control file.
	//L2Rules = rules.GetL3RulesFromORIG("test-separate-l2rules.conf")
	L3Rules = rules.GetL3RulesFromORIG("test-separate-l3rules.conf")

	// Receive packets from 0 port
	flow1 := flow.SetReceiver(uint8(inport))

	// Seperate packet flow based on ACL.
	flow2 := flow.SetSeparator(flow1, L3Separator, nil) // ~66% of packets should go to flow2, ~33% left in flow1

	// Send each flow to corresponding port. Send queues will be added automatically.
	flow.SetSender(flow1, uint8(outport1))
	flow.SetSender(flow2, uint8(outport2))

	// Begin to process packets.
	flow.SystemStart()
}

func L3Separator(pkt *packet.Packet, context flow.UserContext) bool {
	pkt.ParseEtherIPv4UDP()
	return rules.L3_ACL_permit(pkt, L3Rules)
}
