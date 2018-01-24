package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

var l3Rules *packet.L3Rules

func main() {
	var err error
	config := flow.Config{}
	checkFatal(flow.SystemInit(&config))

	initCommonState()

	l3Rules, err = packet.GetL3ACLFromORIG("rules1.conf")
	checkFatal(err)

	firstFlow, err := flow.SetReceiver(0)
	checkFatal(err)
	secondFlow, err := flow.SetSeparator(firstFlow, mySeparator, nil)
	checkFatal(err)
	checkFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	checkFatal(flow.SetSender(firstFlow, 0))
	checkFatal(flow.SetStopper(secondFlow))
	checkFatal(flow.SystemStart())
}

func mySeparator(cur *packet.Packet, ctx flow.UserContext) bool {
	return cur.L3ACLPermit(l3Rules)
}
