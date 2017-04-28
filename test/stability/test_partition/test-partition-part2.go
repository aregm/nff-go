// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/yanff/flow"
)

var (
	inport  uint
	outport1 uint
	outport2 uint
)

// Main function for constructing packet processing graph.
func main() {
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.UintVar(&outport1, "outport1", 0, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")

	// Init YANFF system at 16 available cores.
	flow.SystemInit(16)

	// Receive packets from 0 port
	flow1 := flow.SetReceiver(uint8(inport))

	flow2 := flow.SetPartitioner(flow1, 1000, 100)

	flow.SetSender(flow1, uint8(outport1))
	flow.SetSender(flow2, uint8(outport2))

	// Begin to process packets.
	flow.SystemStart()
}
