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
	l3Rules  *rules.L3Rules
	inport   uint
	outport1 uint
	outport2 uint

	fixMACAddrs1 func(*packet.Packet, flow.UserContext)
	fixMACAddrs2 func(*packet.Packet, flow.UserContext)
)

// Main function for constructing packet processing graph.
func main() {
	// If you modify port numbers with cmd line, provide modified test-split.conf accordingly
	filename := flag.String("FILE", "test-split.conf", "file with split rules in .conf format. If you change default port numbers, please, provide modified rules file too")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.UintVar(&outport1, "outport1", 0, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	configFile := flag.String("config", "config.json", "Specify config file name")
	target := flag.String("target", "nntsat01g4", "Target host name from config file")
	flag.Parse()

	// Init YANFF system at requested number of cores.
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.SystemInit(&config)
	stabilityCommon.InitCommonState(*configFile, *target)
	fixMACAddrs1 = stabilityCommon.ModifyPacket[outport1].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs2 = stabilityCommon.ModifyPacket[outport2].(func(*packet.Packet, flow.UserContext))

	// Get splitting rules from access control file.
	l3Rules = rules.GetL3RulesFromORIG(*filename)

	inputFlow := flow.SetReceiver(uint8(inport))

	// Split packet flow based on ACL.
	flowsNumber := 3
	outputFlows := flow.SetSplitter(inputFlow, l3Splitter, uint(flowsNumber), nil)

	// "0" flow is used for dropping packets without sending them.
	flow.SetStopper(outputFlows[0])

	flow.SetHandler(outputFlows[1], fixPackets1, nil)
	flow.SetHandler(outputFlows[2], fixPackets2, nil)

	// Send each flow to corresponding port. Send queues will be added automatically.
	flow.SetSender(outputFlows[1], uint8(outport1))
	flow.SetSender(outputFlows[2], uint8(outport2))

	// Begin to process packets.
	flow.SystemStart()
}

func l3Splitter(currentPacket *packet.Packet, context flow.UserContext) uint {
	// Return number of flow to which put this packet. Based on ACL rules.
	return rules.L3ACLPort(currentPacket, l3Rules)
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
