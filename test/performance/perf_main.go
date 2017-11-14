// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

import "flag"

var (
	load   uint
	loadRW uint

	inport1     uint
	inport2     uint
	outport1    uint
	outport2    uint
	noscheduler bool
)

func main() {
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	flag.UintVar(&loadRW, "loadRW", 50, "Use this for regulating 'load read/write intensity', number of iterations")

	flag.UintVar(&outport1, "outport1", 1, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	flag.UintVar(&inport1, "inport1", 0, "port for 1st receiver")
	flag.UintVar(&inport2, "inport2", 0, "port for 2nd receiver")
	flag.BoolVar(&noscheduler, "no-scheduler", false, "disable scheduler")
	flag.Parse()

	// Initialize YANFF library at 35 cores by default
	config := flow.Config{
		CPUList:          "0-34",
		DisableScheduler: noscheduler,
	}
	flow.SystemInit(&config)

	// Receive packets from zero port. One queue per receive will be added automatically.
	firstFlow0 := flow.SetReceiver(uint8(inport1))
	firstFlow1 := flow.SetReceiver(uint8(inport2))

	firstFlow := flow.SetMerger(firstFlow0, firstFlow1)

	// Handle second flow via some heavy function
	flow.SetHandler(firstFlow, heavyFunc, nil)

	// Split for two senders and send
	secondFlow := flow.SetPartitioner(firstFlow, 150, 150)

	flow.SetSender(firstFlow, uint8(outport1))
	flow.SetSender(secondFlow, uint8(outport2))

	flow.SystemStart()
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
