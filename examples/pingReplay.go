package main

import (
	"github.com/intel-go/nff-go/flow"
	"flag"
)

func main() {
	inport := flag.Uint("inport", 0, "port for receiver")
        flag.Parse()

	flow.CheckFatal(flow.SystemInit(nil))

	inputFlow, err := flow.SetReceiver(uint16(*inport))
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetIPForPort(uint16(*inport), uint32(20)<<24|uint32(20)<<16|uint32(20)<<8|uint32(20)))

	flow.CheckFatal(flow.DealARPICMP(inputFlow))
	flow.CheckFatal(flow.SetStopper(inputFlow))

	flow.CheckFatal(flow.SystemStart())
}
