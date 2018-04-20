// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"time"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var (
	l2Rules *packet.L2Rules
	l3Rules *packet.L3Rules
	load    uint
)


func main() {
	var err error
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	inport := uint16(*flag.Uint("inport", 0, "port for receiver"))
	outport1 := uint16(*flag.Uint("outport1", 1, "port for 1st sender"))
	outport2 := uint16(*flag.Uint("outport2", 2, "port for 2nd sender"))
	flag.Parse()

	// Initialize NFF-GO library at 16 cores by default
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.CheckFatal(flow.SystemInit(&config))

	// Start regular updating forwarding rules
	l2Rules, err = packet.GetL2ACLFromJSON("demoL2_ACL.json")
	flow.CheckFatal(err)
	l3Rules, err = packet.GetL3ACLFromJSON("demoL3_ACL.json")
	flow.CheckFatal(err)
	go updateSeparateRules()

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow, err := flow.SetReceiver(inport)
	flow.CheckFatal(err)

	// Separate packets for additional flow due to some rules
	secondFlow, err := flow.SetSeparator(firstFlow, l3Separator, nil)
	flow.CheckFatal(err)

	// Handle second flow via some heavy function
	flow.CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))

	// Send both flows each one to one port. Queues will be added automatically.
	flow.CheckFatal(flow.SetSender(firstFlow, outport1))
	flow.CheckFatal(flow.SetSender(secondFlow, outport2))

	flow.CheckFatal(flow.SystemStart())
}

func l3Separator(currentPacket *packet.Packet, context flow.UserContext) bool {
	localL2Rules := l2Rules
	localL3Rules := l3Rules
	return currentPacket.L2ACLPermit(localL2Rules) &&
		currentPacket.L3ACLPermit(localL3Rules)
}

func heavyFunc(currentPacket *packet.Packet, context flow.UserContext) {
	for i := uint(0); i < load; i++ {
	}
}

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		var err error
		l2Rules, err = packet.GetL2ACLFromJSON("demoL2_ACL.json")
		flow.CheckFatal(err)
		l3Rules, err = packet.GetL3ACLFromJSON("demoL3_ACL.json")
		flow.CheckFatal(err)
	}
}
