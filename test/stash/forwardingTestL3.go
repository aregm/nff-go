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

// L3ACL.json assumes that pktgen is configured the following way
//Pktgen> src.ip min 0/1 111.2.0.0
//Pktgen> src.ip max 0/1 111.2.0.4
//Pktgen> src.ip inc 0/1 0.0.0.1
//Pktgen> range.proto 0 udp
//Pktgen> range.proto 1 tcp
//Pktgen> src.port min 0/1 0
//Pktgen> src.port max 0/1 29
//Pktgen> src.port inc 0/1 1
// We need two ports because pktgen can't generate tcp and udp both at one port. So we need to merge them.
// Expected output (to achieve 60GB pktgen should be configured as above + packets per 256B each)
// 0 - 7/30 (if input speed 60GB -> 14GB), always the same as "2"
// 1 - 50% (if input speed 60GB -> 30GB)
// 2 - 7/30 (if input speed 60GB -> 14GB), always the same as "0"
// 3 - 1/30 (if input speed 60GB -> 2GB)
// Pktgen MBits: 13743/30462         28634/29442             13743/0              1955/0           58076/59905

var l3Rules *packet.L3Rules

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	var mode string
	var err error
	flag.StringVar(&mode, "mode", "orig", "Format of rules file")
	flag.Parse()

	// Initialize YANFF library at 16 available cores
	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))

	// Start regular updating forwarding rules
	switch mode {
	case "json":
		l3Rules, err = packet.GetL3ACLFromJSON("forwardingTestL3_ACL.json")
		CheckFatal(err)
	case "orig":
		l3Rules, err = packet.GetL3ACLFromORIG("forwardingTestL3_ACL.orig")
		CheckFatal(err)
	}

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow0, err := flow.SetReceiver(uint8(0))
	CheckFatal(err)
	firstFlow1, err := flow.SetReceiver(uint8(1))
	CheckFatal(err)

	// Merge flows with TCP and UDP packets
	firstFlow, err := flow.SetMerger(firstFlow0, firstFlow1)
	CheckFatal(err)

	// Split packet flow based on ACL
	Flows, err := flow.SetSplitter(firstFlow, l3Splitter, 4, nil)
	CheckFatal(err)

	// Send each flow to corresponding port
	// It is test. So we don't stop "0" packets, we count them as others.
	CheckFatal(flow.SetSender(Flows[0], uint8(0)))
	CheckFatal(flow.SetSender(Flows[1], uint8(1)))
	CheckFatal(flow.SetSender(Flows[2], uint8(2)))
	CheckFatal(flow.SetSender(Flows[3], uint8(3)))

	CheckFatal(flow.SystemStart())
}

func l3Splitter(currentPacket *packet.Packet, context flow.UserContext) uint {
	return currentPacket.L3ACLPort(l3Rules)
}
