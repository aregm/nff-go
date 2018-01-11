// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/intel-go/yanff/flow"
)

var (
	outport uint
	inport  uint
	cores   string
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

// Main function for constructing packet processing graph.
func main() {
	flag.UintVar(&outport, "outport", 1, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.StringVar(&cores, "cores", "0-15", "Specifies CPU cores to be used by YANFF library")

	// Initialize YANFF library at requested cores.
	config := flow.Config{
		CPUList: cores,
	}
	CheckFatal(flow.SystemInit(&config))

	// Receive packets from 0 port and send to 1 port.
	flow1, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)
	CheckFatal(flow.SetSender(flow1, uint8(outport)))

	// Begin to process packets.
	CheckFatal(flow.SystemStart())
}
