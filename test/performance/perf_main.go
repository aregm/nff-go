// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

import "flag"

var load uint
var loadRW uint
var cores uint
var nosched bool

func main() {
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	flag.UintVar(&loadRW, "loadRW", 50, "Use this for regulating 'load read/write intensity', number of iterations")
	flag.UintVar(&cores, "cores", 35, "Number of cores to use by system")
	flag.BoolVar(&nosched, "no-scheduler", false, "Switch scheduler off")

	settings := flow.CreateSettings()
	settings.SchedulerOff = nosched

	// Initialize YANFF library at requested number of cores
	flow.SystemInit(cores, settings)

	// Receive packets from zero port. One queue per receive will be added automatically.
	firstFlow0 := flow.SetReceiver(0)
	firstFlow1 := flow.SetReceiver(0)

	firstFlow := flow.SetMerger(firstFlow0, firstFlow1)

	// Handle second flow via some heavy function
	flow.SetHandler(firstFlow, heavyFunc)

	// Split for two senders and send
	secondFlow := flow.SetPartitioner(firstFlow, 150, 150)
	flow.SetSender(firstFlow, 1)
	flow.SetSender(secondFlow, 1)

	flow.SystemStart()
}

func heavyFunc(currentPacket *packet.Packet) {
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
