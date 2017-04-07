// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

import "flag"

var mode uint
var cores uint
var options = `{"cores": {"Value": 15, "Locked": false}}`

func main() {
	flag.UintVar(&mode, "mode", 0, "Benching mode: 0 - empty, 1 - parsing, 2 - parsing, reading, writing")

	// Initialize YANFF library at requested number of cores
	flow.SystemInit(options)

	// Receive packets from zero port. One queue per receive will be added automatically.
	firstFlow0 := flow.SetReceiver(0)
	firstFlow1 := flow.SetReceiver(0)

	firstFlow := flow.SetMerger(firstFlow0, firstFlow1)

	// Handle second flow via some heavy function
	if mode == 0 {
		flow.SetHandler(firstFlow, heavyFunc0)
	} else if mode == 1 {
		flow.SetHandler(firstFlow, heavyFunc1)
	} else {
		flow.SetHandler(firstFlow, heavyFunc2)
	}

	// Split for two senders and send
	secondFlow := flow.SetPartitioner(firstFlow, 150, 150)
	flow.SetSender(firstFlow, 1)
	flow.SetSender(secondFlow, 1)

	flow.SystemStart()
}

func heavyFunc0(currentPacket *packet.Packet) {
}

func heavyFunc1(currentPacket *packet.Packet) {
	currentPacket.ParseEtherIPv4()
}

func heavyFunc2(currentPacket *packet.Packet) {
	currentPacket.ParseEtherIPv4()
	T := (currentPacket.IPv4.DstAddr)
	currentPacket.IPv4.SrcAddr = 263 + (T)
}
