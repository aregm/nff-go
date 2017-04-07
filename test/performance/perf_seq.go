// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

import "flag"

var load uint
var mode uint
var cores uint
var options = `{"cores": {"Value": 35, "Locked": false}}`

func main() {
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	flag.UintVar(&mode, "mode", 2, "Benching mode: 2, 12 - two handles; 3, 13 - tree handles; 4, 14 - four handles. 2,3,4 - one flow; 12,13,14 - two flows")

	// Initialize YANFF library at requested number of cores
	flow.SystemInit(options)

	var tempFlow *flow.Flow
	var afterFlow *flow.Flow

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow0 := flow.SetReceiver(0)
	firstFlow1 := flow.SetReceiver(0)

	firstFlow := flow.SetMerger(firstFlow0, firstFlow1)
	if mode > 10 {
		tempFlow = flow.SetPartitioner(firstFlow, 150, 150)
	}

	// Handle second flow via some heavy function
	flow.SetHandler(firstFlow, heavyFunc)
	flow.SetHandler(firstFlow, heavyFunc)
	if mode%10 > 2 {
		flow.SetHandler(firstFlow, heavyFunc)
	}
	if mode%10 > 3 {
		flow.SetHandler(firstFlow, heavyFunc)
	}
	if mode > 10 {
		flow.SetHandler(tempFlow, heavyFunc)
		flow.SetHandler(tempFlow, heavyFunc)
		if mode%10 > 2 {
			flow.SetHandler(tempFlow, heavyFunc)
		}
		if mode%10 > 3 {
			flow.SetHandler(tempFlow, heavyFunc)
		}
		afterFlow = flow.SetMerger(firstFlow, tempFlow)
	} else {
		afterFlow = firstFlow
	}
	secondFlow := flow.SetPartitioner(afterFlow, 150, 150)

	// Send both flows each one to one port. Queues will be added automatically.
	flow.SetSender(afterFlow, 1)
	flow.SetSender(secondFlow, 1)

	flow.SystemStart()
}

func heavyFunc(currentPacket *packet.Packet) {
	currentPacket.ParseEtherIPv4()
	T := (currentPacket.IPv4.DstAddr)
	for j := uint(0); j < load; j++ {
		T += uint32(j)
	}
	currentPacket.IPv4.SrcAddr = 263 + (T)
}
