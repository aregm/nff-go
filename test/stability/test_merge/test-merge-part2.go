// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/yanff/flow"
)

var (
	inport1 uint
	inport2 uint
	outport  uint
)

// Main function for constructing packet processing graph.
func main() {
	flag.UintVar(&inport1, "inport1", 0, "port for 1st receiver")
	flag.UintVar(&inport2, "inport2", 1, "port for 2nd receiver")
	flag.UintVar(&outport, "outport", 0, "port for sender")

	// Init YANFF system at requested number of cores.
	flow.SystemInit(16)

	// Receive packets from 0 and 1 ports
	inputFlow1 := flow.SetReceiver(uint8(inport1))
	inputFlow2 := flow.SetReceiver(uint8(inport2))

	outputFlow := flow.SetMerger(inputFlow1, inputFlow2)
	flow.SetSender(outputFlow, uint8(outport))

	// Begin to process packets.
	flow.SystemStart()
}
