// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	"github.com/intel-go/nff-go/flow"
)

var (
	outport uint
	inport  uint
	cores   string
)

// Main function for constructing packet processing graph.
func main() {
	flag.UintVar(&outport, "outport", 1, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.StringVar(&cores, "cores", "", "Specifies CPU cores to be used by NFF-GO library")
	dpdkLogLevel := *(flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL"))

	// Initialize NFF-GO library
	config := flow.Config{
		CPUList:  cores,
		DPDKArgs: []string{dpdkLogLevel},
	}
	flow.CheckFatal(flow.SystemInit(&config))

	// Receive packets from 0 port and send to 1 port.
	flow1, err := flow.SetReceiver(uint8(inport))
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetSender(flow1, uint8(outport)))

	// Begin to process packets.
	flow.CheckFatal(flow.SystemStart())
}
