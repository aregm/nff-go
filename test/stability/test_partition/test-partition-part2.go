// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/intel-go/yanff/flow"
)

var options = `{"cores": {"Value": 16, "Locked": false}}`

// Main function for constructing packet processing graph.
func main() {
	// Init YANFF system at requested number of cores.
	flow.SystemInit(options)

	// Receive packets from 0 port
	flow1 := flow.SetReceiver(0)

	flow2 := flow.SetPartitioner(flow1, 1000, 100)

	flow.SetSender(flow1, 0)
	flow.SetSender(flow2, 1)

	// Begin to process packets.
	flow.SystemStart()
}
