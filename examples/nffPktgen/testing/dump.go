// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"github.com/intel-go/nff-go/examples/nffPktgen/generator"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"os"
)

func main() {
	name := flag.String("m", "", "filename")
	flag.Parse()
	// Init NFF-GO system at 16 available cores
	config := flow.Config{
		CPUList:          "0-43",
		DisableScheduler: true,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	configuration, err := generator.ReadConfig(*name)
	flow.CheckFatal(err)
	context, err1 := generator.GetContext(configuration)
	flow.CheckFatal(err1)

	outFlow, _, _ := flow.SetFastGenerator(generator.Generate, 100, context)
	flow.SetHandler(outFlow, handleRecv, nil)
	flow.SetStopper(outFlow)
	flow.CheckFatal(flow.SystemStart())
}

var got int

func handleRecv(currentPacket *packet.Packet, context flow.UserContext) {
	got++
	fmt.Printf("Raw bytes=%x\n", currentPacket.GetRawPacketBytes())
	if got > 25 {
		os.Exit(0)
	}
}
