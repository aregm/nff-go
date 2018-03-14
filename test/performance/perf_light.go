// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var (
	mode        uint
	inport      uint
	outport1    uint
	outport2    uint
	noscheduler bool
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	flag.UintVar(&mode, "mode", 0, "Benching mode: 0 - empty, 1 - parsing, 2 - parsing, reading, writing")
	flag.UintVar(&outport1, "outport1", 1, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.BoolVar(&noscheduler, "no-scheduler", false, "disable scheduler")
	dpdkLogLevel := *(flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL"))
	flag.Parse()

	// Initialize NFF-GO library
	config := flow.Config{
		DisableScheduler: noscheduler,
		DPDKArgs:         []string{dpdkLogLevel},
	}
	CheckFatal(flow.SystemInit(&config))

	// Receive packets from zero port. One queue per receive will be added automatically.
	firstFlow, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)

	// Handle second flow via some heavy function
	if mode == 0 {
		CheckFatal(flow.SetHandler(firstFlow, heavyFunc0, nil))
	} else if mode == 1 {
		CheckFatal(flow.SetHandler(firstFlow, heavyFunc1, nil))
	} else {
		CheckFatal(flow.SetHandler(firstFlow, heavyFunc2, nil))
	}

	// Split for two senders and send
	secondFlow, err := flow.SetPartitioner(firstFlow, 150, 150)
	CheckFatal(err)

	CheckFatal(flow.SetSender(firstFlow, uint8(outport1)))
	CheckFatal(flow.SetSender(secondFlow, uint8(outport2)))

	CheckFatal(flow.SystemStart())
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
