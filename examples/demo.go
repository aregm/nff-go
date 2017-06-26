// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"
import "github.com/intel-go/yanff/rules"

import "flag"
import "time"

var (
	L2Rules *rules.L2Rules
	L3Rules *rules.L3Rules
	load    uint

	inport  uint
	outport1 uint
	outport2 uint
)

func main() {
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.UintVar(&outport1, "outport1", 1, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 2, "port for 2nd sender")

	// Initialize YANFF library at 16 cores by default
	flow.SystemInit(16)

	// Start regular updating forwarding rules
	L2Rules = rules.GetL2RulesFromJSON("demoL2_ACL.json")
	L3Rules = rules.GetL3RulesFromJSON("demoL3_ACL.json")
	go updateSeparateRules()

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow := flow.SetReceiver(uint8(inport))

	// Separate packets for additional flow due to some rules
	secondFlow := flow.SetSeparator(firstFlow, L3Separator, nil)

	// Handle second flow via some heavy function
	flow.SetHandler(firstFlow, heavyFunc, nil)

	// Send both flows each one to one port. Queues will be added automatically.
	flow.SetSender(firstFlow, uint8(outport1))
	flow.SetSender(secondFlow, uint8(outport2))

	flow.SystemStart()
}

func L3Separator(currentPacket *packet.Packet, context flow.UserContext) bool {
	currentPacket.ParseEtherIPv4()
	localL2Rules := L2Rules
	localL3Rules := L3Rules
	return rules.L2_ACL_permit(currentPacket, localL2Rules) &&
		rules.L3_ACL_permit(currentPacket, localL3Rules)
}

func heavyFunc(currentPacket *packet.Packet, context flow.UserContext) {
	for i := uint(0); i < load; i++ {
	}
}

func updateSeparateRules() {
	for true {
		time.Sleep(time.Second * 5)
		L2Rules = rules.GetL2RulesFromJSON("demoL2_ACL.json")
		L3Rules = rules.GetL3RulesFromJSON("demoL3_ACL.json")
	}
}
