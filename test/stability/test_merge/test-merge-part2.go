// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/intel-go/yanff/flow"
)

// Main function for constructing packet processing graph.
func main() {
	// Init YANFF system
	flow.SystemInit(16)

	// Receive packets from 0 and 1 ports
	inputFlow1 := flow.SetReceiver(0)
	inputFlow2 := flow.SetReceiver(1)

	outputFlow := flow.SetMerger(inputFlow1, inputFlow2)

	flow.SetSender(outputFlow, 0)

	// Begin to process packets.
	flow.SystemStart()
}
