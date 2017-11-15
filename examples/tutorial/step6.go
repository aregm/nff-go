package main

import (
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var (
	l3Rules *packet.L3Rules
)

func main() {
	config := flow.Config{}
	flow.SystemInit(&config)
	initCommonState()
	l3Rules = packet.GetL3ACLFromORIG("rules1.conf")
	firstFlow := flow.SetReceiver(0)
	secondFlow := flow.SetSeparator(firstFlow, mySeparator, nil)
	flow.SetHandler(firstFlow, modifyPacket[0], nil)
	flow.SetSender(firstFlow, 0)
	flow.SetStopper(secondFlow)
	flow.SystemStart()
}

func mySeparator(cur *packet.Packet, ctx flow.UserContext) bool {
	return cur.L3ACLPermit(l3Rules)
}
