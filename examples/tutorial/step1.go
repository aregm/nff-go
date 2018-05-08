package main

import "github.com/intel-go/nff-go/flow"

func main() {
	// Init NFF-GO system
	config := flow.Config{}
	flow.CheckFatal(flow.SystemInit(&config))

	initCommonState()

	flow.CheckFatal(flow.SystemStart())
}
