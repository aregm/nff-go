// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/intel-go/nff-go/flow"
)

var inport, outport uint
var cores string

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

// This is a test for pure send/receive performance measurements. No
// other functions used here.
func main() {
	flag.UintVar(&inport, "inport", 0, "Input port number")
	flag.UintVar(&outport, "outport", 0, "Output port number")
	flag.StringVar(&cores, "cores", "", "Specifies CPU cores to be used by NFF-GO library")
	dpdkLogLevel := *(flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL"))
	flag.Parse()

	// Initialize NFF-GO library
	config := flow.Config{
		CPUList:  cores,
		DPDKArgs: []string{dpdkLogLevel},
	}
	CheckFatal(flow.SystemInit(&config))

	// Receive packets from input port. One queue will be added automatically.
	f, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)

	CheckFatal(flow.SetSender(f, uint8(outport)))

	CheckFatal(flow.SystemStart())
}
