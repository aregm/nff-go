package main

import (
	"flag"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/types"
)

func main() {
	inport := flag.Uint("inport", 0, "port for receiver")
	flag.Parse()

	flow.CheckFatal(flow.SystemInit(nil))

	inputFlow, err := flow.SetReceiver(uint16(*inport))
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetIPForPort(uint16(*inport), types.IPv4Address(20)<<24|types.IPv4Address(20)<<16|types.IPv4Address(20)<<8|types.IPv4Address(20)))

	flow.CheckFatal(flow.DealARPICMP(inputFlow))
	flow.CheckFatal(flow.SetStopper(inputFlow))

	flow.CheckFatal(flow.SystemStart())
}
