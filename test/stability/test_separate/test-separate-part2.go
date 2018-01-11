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
)

var (
	l3Rules *packet.L3Rules

	inport   uint
	outport1 uint
	outport2 uint

	fixMACAddrs1 func(*packet.Packet, flow.UserContext)
	fixMACAddrs2 func(*packet.Packet, flow.UserContext)
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
	var err error
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.UintVar(&outport1, "outport1", 0, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	configFile := flag.String("config", "config.json", "Specify config file name")
	target := flag.String("target", "nntsat01g4", "Target host name from config file")
	flag.Parse()

	// Init YANFF system at 16 available cores.
	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))
	stabilityCommon.InitCommonState(*configFile, *target)
	fixMACAddrs1 = stabilityCommon.ModifyPacket[outport1].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs2 = stabilityCommon.ModifyPacket[outport2].(func(*packet.Packet, flow.UserContext))

	// Get splitting rules from access control file.
	l3Rules, err = packet.GetL3ACLFromORIG("test-separate-l3rules.conf")
	CheckFatal(err)

	// Receive packets from 0 port
	flow1, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)

	// Separate packet flow based on ACL.
	flow2, err := flow.SetSeparator(flow1, l3Separator, nil) // ~66% of packets should go to flow2, ~33% left in flow1
	CheckFatal(err)

	CheckFatal(flow.SetHandler(flow1, fixPackets1, nil))
	CheckFatal(flow.SetHandler(flow2, fixPackets2, nil))

	// Send each flow to corresponding port. Send queues will be added automatically.
	CheckFatal(flow.SetSender(flow1, uint8(outport1)))
	CheckFatal(flow.SetSender(flow2, uint8(outport2)))

	// Begin to process packets.
	CheckFatal(flow.SystemStart())
}

func l3Separator(pkt *packet.Packet, context flow.UserContext) bool {
	return pkt.L3ACLPermit(l3Rules)
}

func fixPackets1(pkt *packet.Packet, ctx flow.UserContext) {
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	fixMACAddrs1(pkt, ctx)
}

func fixPackets2(pkt *packet.Packet, ctx flow.UserContext) {
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	fixMACAddrs2(pkt, ctx)
}
