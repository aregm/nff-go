package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

func main() {
	config := flow.Config{}
	checkFatal(flow.SystemInit(&config))

	initCommonState()

	firstFlow, err := flow.SetReceiver(0)
	checkFatal(err)
	secondFlow, err := flow.SetSeparator(firstFlow, mySeparator, nil)
	checkFatal(err)
	checkFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	checkFatal(flow.SetHandler(secondFlow, modifyPacket[1], nil))
	checkFatal(flow.SetSender(firstFlow, 0))
	checkFatal(flow.SetSender(secondFlow, 1))

	checkFatal(flow.SystemStart())
}

func mySeparator(cur *packet.Packet, ctx flow.UserContext) bool {
	cur.ParseL3()
	if cur.GetIPv4() != nil {
		cur.ParseL4ForIPv4()
		if cur.GetTCPForIPv4() != nil && packet.SwapBytesUint16(cur.GetTCPForIPv4().DstPort) == 53 {
			return false
		}
	}
	return true
}
