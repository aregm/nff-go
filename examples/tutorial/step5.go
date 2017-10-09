package main

import (
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"github.com/intel-go/yanff/rules"
)

var (
	l3Rules *rules.L3Rules
)

func main() {
	config := flow.Config{}
	flow.SystemInit(&config)
	initCommonState()
	l3Rules = rules.GetL3RulesFromORIG("rules1.conf")
	firstFlow := flow.SetReceiver(0)
	secondFlow := flow.SetSeparator(firstFlow, mySeparator, nil)
	flow.SetHandler(firstFlow, modifyPacket[0], nil)
	flow.SetHandler(secondFlow, modifyPacket[1], nil)
	flow.SetSender(firstFlow, 0)
	flow.SetSender(secondFlow, 1)
	flow.SystemStart()
}

func mySeparator(cur *packet.Packet, ctx flow.UserContext) bool {
	return rules.L3ACLPermit(cur, l3Rules)
}
