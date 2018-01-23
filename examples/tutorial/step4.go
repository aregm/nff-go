package main

import (
	"fmt"
	"os"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}
func main() {
	config := flow.Config{}
	CheckFatal(flow.SystemInit(&config))

	initCommonState()

	firstFlow, err := flow.SetReceiver(uint8(0))
	CheckFatal(err)
	secondFlow, err := flow.SetSeparator(firstFlow, mySeparator, nil)
	CheckFatal(err)
	CheckFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	CheckFatal(flow.SetHandler(secondFlow, modifyPacket[1], nil))
	CheckFatal(flow.SetSender(firstFlow, uint8(0)))
	CheckFatal(flow.SetSender(secondFlow, uint8(1)))

	CheckFatal(flow.SystemStart())
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
