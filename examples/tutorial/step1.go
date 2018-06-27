package main

import "github.com/intel-go/nff-go/flow"

func main() {
	// Init NFF-GO system
	flow.CheckFatal(flow.SystemInit(nil))

	initCommonState()

	flow.CheckFatal(flow.SystemStart())
}
