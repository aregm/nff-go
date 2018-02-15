package main

import "github.com/intel-go/nff-go/flow"

func main() {
	// Init NFF-GO system
	config := flow.Config{}
	checkFatal(flow.SystemInit(&config))

	initCommonState()

	checkFatal(flow.SystemStart())
}
