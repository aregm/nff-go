// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/flow"

import "flag"

var inport, outport uint
var cores uint

// This is a test for pure send/receive performance measurements. No
// other functions used here.
func main() {
	flag.UintVar(&inport, "inport", 0, "Input port number")
	flag.UintVar(&outport, "outport", 0, "Output port number")
	flag.UintVar(&cores, "cores", 16, "Number of cores to use by system")

	// Initialize YANFF library at requested number of cores
	flow.SystemInit(cores)

	// Receive packets from input port. One queue will be added automatically.
	f := flow.SetReceiver(uint8(inport))

	flow.SetSender(f, uint8(outport))

	flow.SystemStart()
}
