// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"

	"github.com/intel-go/yanff/test/stability/stabilityCommon"
	"github.com/intel-go/yanff/test/stability/test1/common"
)

var (
	cores   uint
	outport uint
	inport  uint

	fixMACAddrs func(*packet.Packet, flow.UserContext)
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

// Main function for constructing packet processing graph.
func main() {
	flag.UintVar(&inport, "inport", 0, "port for receiver (0 or 1)")
	flag.UintVar(&outport, "outport", 1, "port for sender (0 or 1)")
	configFile := flag.String("config", "config.json", "Specify config file name")
	target := flag.String("target", "nntsat01g4", "Target host name from config file")
	flag.Parse()

	// Init YANFF system at 16 available cores.
	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))

	stabilityCommon.InitCommonState(*configFile, *target)
	fixMACAddrs = stabilityCommon.ModifyPacket[outport].(func(*packet.Packet, flow.UserContext))

	inputFlow, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)
	CheckFatal(flow.SetHandler(inputFlow, fixPacket, nil))
	CheckFatal(flow.SetSender(inputFlow, uint8(outport)))

	// Begin to process packets.
	CheckFatal(flow.SystemStart())
}

func fixPacket(pkt *packet.Packet, context flow.UserContext) {
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	fixMACAddrs(pkt, context)

	res := pkt.ParseData()
	if res < 0 {
		println("ParseL4 returned negative value", res)
		println("TEST FAILED")
		return
	}

	ptr := (*common.Packetdata)(pkt.Data)
	if ptr.F2 != 0 {
		fmt.Printf("Bad data found in the packet: %x\n", ptr.F2)
		println("TEST FAILED")
		return
	}

	ptr.F2 = ptr.F1
}
