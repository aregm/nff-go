// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

import "flag"

var load uint
var loadRW uint

func main() {
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	flag.UintVar(&loadRW, "loadRW", 50, "Use this for regulating 'load read/write intensity', number of iterations")

	// Initialize YANFF library at 35 cores by default
	flow.SystemInit(35)

	// Receive packets from zero port. One queue per receive will be added automatically.
	firstFlow0 := flow.SetReceiver(0)
	firstFlow1 := flow.SetReceiver(0)

	firstFlow := flow.SetMerger(firstFlow0, firstFlow1)

	// Handle second flow via some heavy function
	flow.SetHandler(firstFlow, heavyFunc, nil)

	// Split for two senders and send
	secondFlow := flow.SetPartitioner(firstFlow, 150, 150)
	flow.SetSender(firstFlow, 1)
	flow.SetSender(secondFlow, 1)

	flow.SystemStart()
}

func heavyFunc(currentPacket *packet.Packet, context flow.UserContext) {
	currentPacket.ParseEtherIPv4()
	T := currentPacket.IPv4.DstAddr
	for j := uint32(0); j < uint32(load); j++ {
		T += j
	}
	for i := uint32(0); i < uint32(loadRW); i++ {
		currentPacket.IPv4.DstAddr = currentPacket.IPv4.SrcAddr + i
	}
	currentPacket.IPv4.SrcAddr = 263 + (T)
}
