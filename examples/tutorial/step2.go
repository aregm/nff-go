package main

import "github.com/intel-go/yanff/flow"

func main() {
	config := flow.Config{}
	checkFatal(flow.SystemInit(&config))

	initCommonState()

	firstFlow, err := flow.SetReceiver(0)
	checkFatal(err)
	checkFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	checkFatal(flow.SetSender(firstFlow, 0))

	checkFatal(flow.SystemStart())
}
