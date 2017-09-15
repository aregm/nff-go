package main

import (
	"github.com/intel-go/yanff/flow"
)

func main() {
	// Init YANFF system
	config := flow.Config{}
	flow.SystemInit(&config)

	initCommonState()

	flow.SystemStart()
}
