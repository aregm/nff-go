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
)

var (
	l3Rules *packet.L3Rules

	outport uint
	inport  uint
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
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.Parse()

	// Init YANFF system at 16 available cores.
	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))

	// Get splitting rules from access control file.
	l3Rules, err = packet.GetL3ACLFromORIG("test-handle2-l3rules.conf")
	CheckFatal(err)

	// Receive packets from 0 port
	flow1, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)

	// Handle packet flow
	// ~33% of packets should left in flow1
	CheckFatal(flow.SetHandlerDrop(flow1, l3Handler, nil))

	// Send each flow to corresponding port. Send queues will be added automatically.
	CheckFatal(flow.SetSender(flow1, uint8(outport)))

	// Begin to process packets.
	CheckFatal(flow.SystemStart())
}

func l3Handler(pkt *packet.Packet, context flow.UserContext) bool {
	return pkt.L3ACLPermit(l3Rules)
}
