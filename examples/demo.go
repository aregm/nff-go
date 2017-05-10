// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"
import "github.com/intel-go/yanff/rules"

import "flag"
import "time"

var L2Rules *rules.L2Rules
var L3Rules *rules.L3Rules
var load uint
var options = `{"cores": {"Value": 16, "Locked": false}}`

func main() {
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")

	// Initialize YANFF library at requested number of cores
	flow.SystemInit(options)

	// Start regular updating forwarding rules
	L2Rules = rules.GetL2RulesFromJSON("demoL2_ACL.json")
	L3Rules = rules.GetL3RulesFromJSON("demoL3_ACL.json")
	go updateSeparateRules()

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow := flow.SetReceiver(0)

	// Separate packets for additional flow due to some rules
	secondFlow := flow.SetSeparator(firstFlow, L3Separator)

	// Handle second flow via some heavy function
	flow.SetHandler(firstFlow, heavyFunc)

	// Send both flows each one to one port. Queues will be added automatically.
	flow.SetSender(firstFlow, 1)
	flow.SetSender(secondFlow, 2)

	flow.SystemStart()
}

func L3Separator(currentPacket *packet.Packet) bool {
	currentPacket.ParseEtherIPv4()
	localL2Rules := L2Rules
	localL3Rules := L3Rules
	return rules.L2_ACL_permit(currentPacket, localL2Rules) &&
		rules.L3_ACL_permit(currentPacket, localL3Rules)
}

func heavyFunc(currentPacket *packet.Packet) {
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
