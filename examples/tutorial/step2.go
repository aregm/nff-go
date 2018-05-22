package main

import "github.com/intel-go/nff-go/flow"

func main() {
	flow.CheckFatal(flow.SystemInit(nil))

	initCommonState()

	firstFlow, err := flow.SetReceiver(0)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	flow.CheckFatal(flow.SetSender(firstFlow, 0))

	flow.CheckFatal(flow.SystemStart())
}
