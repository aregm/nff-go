package main

import "github.com/intel-go/yanff/flow"

func main() {
	config := flow.Config{}
	flow.SystemInit(&config)

	initCommonState()

	firstFlow := flow.SetReceiver(0)
	flow.SetHandler(firstFlow, modifyPacket[0], nil)
	flow.SetSender(firstFlow, 0)

	flow.SystemStart()
}
