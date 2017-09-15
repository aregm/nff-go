package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

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
	cur.ParseIPv4TCP()
	if packet.SwapBytesUint16(cur.TCP.DstPort) == 53 {
		return false
	} else {
		return true
	}
}
