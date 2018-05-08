package main

import "github.com/intel-go/nff-go/flow"
import "github.com/intel-go/nff-go/packet"

func main() {
	config := flow.Config{}
	flow.CheckFatal(flow.SystemInit(&config))

	initCommonState()

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
	cur.ParseL3()
	if cur.GetIPv4() != nil {
		cur.ParseL4ForIPv4()
		if cur.GetTCPForIPv4() != nil && packet.SwapBytesUint16(cur.GetTCPForIPv4().DstPort) == 53 {
			return false
		}
	}
	return true
}
