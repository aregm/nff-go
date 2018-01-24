package main

import "github.com/intel-go/yanff/flow"

func main() {
	// Init YANFF system
	config := flow.Config{}
	checkFatal(flow.SystemInit(&config))

	initCommonState()

	checkFatal(flow.SystemStart())
}
