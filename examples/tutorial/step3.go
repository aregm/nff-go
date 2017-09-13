package main

import "github.com/intel-go/yanff/flow"

func main() {
	config := flow.Config{}
	flow.SystemInit(&config)

	initCommonState()

	firstFlow := flow.SetReceiver(0)
	secondFlow := flow.SetPartitioner(firstFlow, 300, 300)
	flow.SetHandler(firstFlow, modifyPacket[0], nil)
	flow.SetHandler(secondFlow, modifyPacket[1], nil)
	flow.SetSender(firstFlow, 0)
	flow.SetSender(secondFlow, 1)

	flow.SystemStart()
}
