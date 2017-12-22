// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var (
	l2Rules *packet.L2Rules
	l3Rules *packet.L3Rules
	load    uint

	inport   uint
	outport1 uint
	outport2 uint
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	var err error
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.UintVar(&outport1, "outport1", 1, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 2, "port for 2nd sender")
	flag.Parse()

	// Initialize YANFF library at 16 cores by default
	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))

	// Start regular updating forwarding rules
	l2Rules, err = packet.GetL2ACLFromJSON("demoL2_ACL.json")
	CheckFatal(err)
	l3Rules, err = packet.GetL3ACLFromJSON("demoL3_ACL.json")
	CheckFatal(err)
	go updateSeparateRules()

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)

	// Separate packets for additional flow due to some rules
	secondFlow, err := flow.SetSeparator(firstFlow, l3Separator, nil)
	CheckFatal(err)

	// Handle second flow via some heavy function
	CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))

	// Send both flows each one to one port. Queues will be added automatically.
	CheckFatal(flow.SetSender(firstFlow, uint8(outport1)))
	CheckFatal(flow.SetSender(secondFlow, uint8(outport2)))

	CheckFatal(flow.SystemStart())
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
		CheckFatal(err)
		l3Rules, err = packet.GetL3ACLFromJSON("demoL3_ACL.json")
		CheckFatal(err)
	}
}
