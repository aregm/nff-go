// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/flow"

import "flag"

var inport, outport, cores uint

// This is a test for pure send/receive performance measurements. No
// other functions used here.
func main() {
	flag.UintVar(&inport, "inport", 0, "Input port number")
	flag.UintVar(&outport, "outport", 0, "Output port number")
	flag.UintVar(&cores, "cores", 16, "Specifies number of CPU cores to be used by YANFF library")
	flag.Parse()

	// Initialize YANFF library to use specified number of CPU cores
	config := flow.Config {
		CPUCoresNumber: cores,
	}
	flow.SystemInit(&config)

	// Receive packets from input port. One queue will be added automatically.
	f := flow.SetReceiver(uint8(inport))

	flow.SetSender(f, uint8(outport))

	flow.SystemStart()
}
