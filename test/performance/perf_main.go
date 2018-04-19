// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var (
	load        uint
	loadRW      uint
)

func main() {
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	flag.UintVar(&loadRW, "loadRW", 50, "Use this for regulating 'load read/write intensity', number of iterations")

	outport1 := uint16(*flag.Uint("outport1", 1, "port for 1st sender"))
	outport2 := uint16(*flag.Uint("outport2", 1, "port for 2nd sender"))
	inport := uint16(*flag.Uint("inport", 0, "port for receiver"))
	noscheduler := *flag.Bool("no-scheduler", false, "disable scheduler")
	dpdkLogLevel := *flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()

	// Initialize NFF-GO library
	config := flow.Config{
		DisableScheduler: noscheduler,
		DPDKArgs:         []string{dpdkLogLevel},
	}
	flow.CheckFatal(flow.SystemInit(&config))

	// Receive packets from zero port. One queue per receive will be added automatically.
	firstFlow, err := flow.SetReceiver(inport)
	flow.CheckFatal(err)

	// Handle second flow via some heavy function
	flow.CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))

	// Split for two senders and send
	secondFlow, err := flow.SetPartitioner(firstFlow, 150, 150)
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetSender(firstFlow, outport1))
	flow.CheckFatal(flow.SetSender(secondFlow, outport2))

	flow.CheckFatal(flow.SystemStart())
}

func heavyFunc(currentPacket *packet.Packet, context flow.UserContext) {
	currentPacket.ParseL3()
	ipv4 := currentPacket.GetIPv4()
	if ipv4 != nil {
		T := ipv4.DstAddr
		for j := uint32(0); j < uint32(load); j++ {
			T += j
		}
		for i := uint32(0); i < uint32(loadRW); i++ {
			ipv4.DstAddr = ipv4.SrcAddr + i
		}
		ipv4.SrcAddr = 263 + (T)
	}
}
