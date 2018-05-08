// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

func main() {
	var mode uint
	flag.UintVar(&mode, "mode", 0, "Benching mode: 0 - empty, 1 - parsing, 2 - parsing, reading, writing")
	outport1 := flag.Uint("outport1", 1, "port for 1st sender")
	outport2 := flag.Uint("outport2", 1, "port for 2nd sender")
	inport := flag.Uint("inport", 0, "port for receiver")
	noscheduler := flag.Bool("no-scheduler", false, "disable scheduler")
	dpdkLogLevel := flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()

	// Initialize NFF-GO library
	config := flow.Config{
		DisableScheduler: *noscheduler,
		DPDKArgs:         []string{*dpdkLogLevel},
	}
	flow.CheckFatal(flow.SystemInit(&config))

	// Receive packets from zero port. One queue per receive will be added automatically.
	firstFlow, err := flow.SetReceiver(uint16(*inport))
	flow.CheckFatal(err)

	// Handle second flow via some heavy function
	if mode == 0 {
		flow.CheckFatal(flow.SetHandler(firstFlow, heavyFunc0, nil))
	} else if mode == 1 {
		flow.CheckFatal(flow.SetHandler(firstFlow, heavyFunc1, nil))
	} else {
		flow.CheckFatal(flow.SetHandler(firstFlow, heavyFunc2, nil))
	}

	// Split for two senders and send
	secondFlow, err := flow.SetPartitioner(firstFlow, 150, 150)
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetSender(firstFlow, uint16(*outport1)))
	flow.CheckFatal(flow.SetSender(secondFlow, uint16(*outport2)))

	flow.CheckFatal(flow.SystemStart())
}

func heavyFunc0(currentPacket *packet.Packet, context flow.UserContext) {
}

func heavyFunc1(currentPacket *packet.Packet, context flow.UserContext) {
	currentPacket.ParseL3()
}

func heavyFunc2(currentPacket *packet.Packet, context flow.UserContext) {
	currentPacket.ParseL3()
	ipv4 := currentPacket.GetIPv4()
	if ipv4 != nil {
		T := ipv4.DstAddr
		ipv4.SrcAddr = 263 + (T)
	}
}
