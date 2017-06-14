// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"

	"github.com/intel-go/yanff/test/stability/test1/common"
)

// Main function for constructing packet processing graph.
func main() {
	// Init YANFF system
	flow.SystemInit(16)

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow := flow.SetReceiver(0)
	flow.SetHandler(inputFlow, fixPacket, nil)
	flow.SetSender(inputFlow, 1)

	// Begin to process packets.
	flow.SystemStart()
}

func fixPacket(pkt *packet.Packet, context flow.UserContext) {
	offset := pkt.ParseL4Data()
	if offset < 0 {
		println("ParseL4 returned negative value", offset)
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
