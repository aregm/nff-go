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
	//L2Rules = rules.GetL3RulesFromORIG("test-handle2-l2rules.conf")
	L3Rules = rules.GetL3RulesFromORIG("test-handle2-l3rules.conf")

	// Receive packets from 0 port
	flow1 := flow.SetReceiver(0)

	// Handle packet flow
	flow.SetHandler(flow1, L3Handler) // ~33% of packets should left in flow1

	// Send each flow to corresponding port. Send queues will be added automatically.
	flow.SetSender(flow1, 0)

	// Begin to process packets.
	flow.SystemStart()
}

func L3Handler(pkt *packet.Packet) bool {
	pkt.ParseEtherIPv4UDP()
	return rules.L3_ACL_permit(pkt, L3Rules)
}
