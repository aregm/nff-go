// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	"github.com/intel-go/nff-go/flow"
)

// This is a test for pure send/receive performance measurements. No
// other functions used here.
func main() {
	inport := uint16(*flag.Uint("inport", 0, "Input port number"))
	outport := uint16(*flag.Uint("outport", 0, "Output port number"))
	cores := *flag.String("cores", "", "Specifies CPU cores to be used by NFF-GO library")
	dpdkLogLevel := *flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()

	// Initialize NFF-GO library
	config := flow.Config{
		CPUList:  cores,
		DPDKArgs: []string{dpdkLogLevel},
	}
	flow.CheckFatal(flow.SystemInit(&config))

	// Receive packets from input port. One queue will be added automatically.
	f, err := flow.SetReceiver(inport)
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetSender(f, outport))

	flow.CheckFatal(flow.SystemStart())
}
