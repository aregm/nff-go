package main

import (
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

func main() {
	config := flow.Config{}
	flow.SystemInit(&config)

	initCommonState()

	firstFlow := flow.SetReceiver(0)
	secondFlow := flow.SetSeparator(firstFlow, mySeparator, nil)
	flow.SetHandler(firstFlow, modifyPacket[0], nil)
	flow.SetHandler(secondFlow, modifyPacket[1], nil)
	flow.SetSender(firstFlow, 0)
	flow.SetSender(secondFlow, 1)

	flow.SystemStart()
}

func mySeparator(cur *packet.Packet, ctx flow.UserContext) bool {
	cur.ParseL3()
	if cur.GetIPv4() != nil && cur.GetTCPForIPv4() != nil && packet.SwapBytesUint16(cur.GetTCPForIPv4().DstPort) == 53 {
		return false
	}
	return true
}
