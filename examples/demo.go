// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"time"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"github.com/intel-go/yanff/rules"
)

var (
	l2Rules *rules.L2Rules
	l3Rules *rules.L3Rules
	load    uint

	inport   uint
	outport1 uint
	outport2 uint
)

func main() {
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.UintVar(&outport1, "outport1", 1, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 2, "port for 2nd sender")
	flag.Parse()

	// Initialize YANFF library at 16 cores by default
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.SystemInit(&config)

	// Start regular updating forwarding rules
	l2Rules = rules.GetL2RulesFromJSON("demoL2_ACL.json")
	l3Rules = rules.GetL3RulesFromJSON("demoL3_ACL.json")
	go updateSeparateRules()

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow := flow.SetReceiver(uint8(inport))

	// Separate packets for additional flow due to some rules
	secondFlow := flow.SetSeparator(firstFlow, l3Separator, nil)

	// Handle second flow via some heavy function
	flow.SetHandler(firstFlow, heavyFunc, nil)

	// Send both flows each one to one port. Queues will be added automatically.
	flow.SetSender(firstFlow, uint8(outport1))
	flow.SetSender(secondFlow, uint8(outport2))

	flow.SystemStart()
}

func l3Separator(currentPacket *packet.Packet, context flow.UserContext) bool {
	localL2Rules := l2Rules
	localL3Rules := l3Rules
	return rules.L2ACLPermit(currentPacket, localL2Rules) &&
		rules.L3ACLPermit(currentPacket, localL3Rules)
}

func heavyFunc(currentPacket *packet.Packet, context flow.UserContext) {
	for i := uint(0); i < load; i++ {
	}
}

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		l2Rules = rules.GetL2RulesFromJSON("demoL2_ACL.json")
		l3Rules = rules.GetL3RulesFromJSON("demoL3_ACL.json")
	}
}
