// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/yanff/flow"
)

var filename string
var outport uint
var repcount int

func main() {
	flag.StringVar(&filename, "filename", "rw_example.pcap", "Input pcap file")
	flag.IntVar(&repcount, "repcnt", 1, "Number of times the file will be read")
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.Parse()

	// Initialize YANFF library at 16 cores by default
	config := flow.Config{
		CPUCoresNumber: 16,
	}
	flow.SystemInit(&config)

	f1 := flow.SetReader(filename, int32(repcount))
	flow.SetSender(f1, uint8(outport))

	flow.SystemStart()
}
