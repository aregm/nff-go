// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/yanff/flow"
)

var (
	outport uint
	inport uint
)

// Main function for constructing packet processing graph.
func main() {
	flag.UintVar(&outport, "outport", 1, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")

	// Initialize YANFF library at requested number of cores.
	flow.SystemInit(16)

	// Receive packets from 0 port and send to 1 port.
	flow1 := flow.SetReceiver(uint8(inport))
	flow.SetSender(flow1, uint8(outport))

	// Begin to process packets.
	flow.SystemStart()
}
