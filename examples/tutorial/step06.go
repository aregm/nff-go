package main

import "github.com/intel-go/nff-go/flow"
import "github.com/intel-go/nff-go/packet"

var l3Rules *packet.L3Rules

func main() {
	var err error
	flow.CheckFatal(flow.SystemInit(nil))

	initCommonState()

	l3Rules, err = packet.GetL3ACLFromTextTable("rules1.conf")
	flow.CheckFatal(err)

	firstFlow, err := flow.SetReceiver(0)
	flow.CheckFatal(err)
	secondFlow, err := flow.SetSeparator(firstFlow, mySeparator, nil)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	flow.CheckFatal(flow.SetSender(firstFlow, 0))
	flow.CheckFatal(flow.SetStopper(secondFlow))
	flow.CheckFatal(flow.SystemStart())
}

func mySeparator(cur *packet.Packet, ctx flow.UserContext) bool {
	return cur.L3ACLPermit(l3Rules)
}
