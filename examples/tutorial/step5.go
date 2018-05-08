package main

import "github.com/intel-go/nff-go/flow"
import "github.com/intel-go/nff-go/packet"

var l3Rules *packet.L3Rules

func main() {
	var err error
	config := flow.Config{}
	flow.CheckFatal(flow.SystemInit(&config))

	initCommonState()

	l3Rules, err = packet.GetL3ACLFromORIG("rules1.conf")
	flow.CheckFatal(err)

	firstFlow, err := flow.SetReceiver(0)
	flow.CheckFatal(err)
	secondFlow, err := flow.SetSeparator(firstFlow, mySeparator, nil)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	flow.CheckFatal(flow.SetHandler(secondFlow, modifyPacket[1], nil))
	flow.CheckFatal(flow.SetSender(firstFlow, 0))
	flow.CheckFatal(flow.SetSender(secondFlow, 1))
	flow.CheckFatal(flow.SystemStart())
}

func mySeparator(cur *packet.Packet, ctx flow.UserContext) bool {
	return cur.L3ACLPermit(l3Rules)
}
