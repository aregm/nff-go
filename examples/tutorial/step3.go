package main

import (
	"fmt"
	"os"

	"github.com/intel-go/yanff/flow"
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
	secondFlow, err := flow.SetPartitioner(firstFlow, 300, 300)
	CheckFatal(err)
	CheckFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	CheckFatal(flow.SetHandler(secondFlow, modifyPacket[1], nil))
	CheckFatal(flow.SetSender(firstFlow, uint8(0)))
	CheckFatal(flow.SetSender(secondFlow, uint8(1)))

	CheckFatal(flow.SystemStart())
}
