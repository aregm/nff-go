// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/intel-go/yanff/flow"
)

// Main function for constructing packet processing graph.
func main() {
	// Initialize YANFF library at 16 available cores.
	flow.SystemInit(16)

	// Receive packets from 0 port and send to 1 port.
	flow1 := flow.SetReceiver(0)
	flow.SetSender(flow1, 1)

	// Begin to process packets.
	flow.SystemStart()
}
