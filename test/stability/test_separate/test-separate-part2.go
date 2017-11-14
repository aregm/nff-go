// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"github.com/intel-go/yanff/rules"
	"github.com/intel-go/yanff/test/stability/stabilityCommon"
)

var (
	l3Rules *rules.L3Rules

	inport   uint
	outport1 uint
	outport2 uint

	fixMACAddrs1 func(*packet.Packet, flow.UserContext)
	fixMACAddrs2 func(*packet.Packet, flow.UserContext)
)

// Main function for constructing packet processing graph.
func main() {
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
	flow.SystemInit(&config)
	stabilityCommon.InitCommonState(*configFile, *target)
	fixMACAddrs1 = stabilityCommon.ModifyPacket[outport1].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs2 = stabilityCommon.ModifyPacket[outport2].(func(*packet.Packet, flow.UserContext))

	// Get splitting rules from access control file.
	//L2Rules = rules.GetL3RulesFromORIG("test-separate-l2rules.conf")
	l3Rules = rules.GetL3RulesFromORIG("test-separate-l3rules.conf")

	// Receive packets from 0 port
	flow1 := flow.SetReceiver(uint8(inport))

	// Separate packet flow based on ACL.
	flow2 := flow.SetSeparator(flow1, l3Separator, nil) // ~66% of packets should go to flow2, ~33% left in flow1

	flow.SetHandler(flow1, fixPackets1, nil)
	flow.SetHandler(flow2, fixPackets2, nil)

	// Send each flow to corresponding port. Send queues will be added automatically.
	flow.SetSender(flow1, uint8(outport1))
	flow.SetSender(flow2, uint8(outport2))

	// Begin to process packets.
	flow.SystemStart()
}

func l3Separator(pkt *packet.Packet, context flow.UserContext) bool {
	return rules.L3ACLPermit(pkt, l3Rules)
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
