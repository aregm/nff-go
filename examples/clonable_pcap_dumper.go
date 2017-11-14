// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var (
	outport uint
	inport  uint

	cloneNumber uint
)

func main() {
	flag.UintVar(&outport, "outport", 1, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.Parse()

	// Initialize YANFF library at 10 available cores
	config := flow.Config{
		CPUList: "0-9",
	}
	flow.SystemInit(&config)

	// Receive packets from zero port. One queue will be added automatically.
	f1 := flow.SetReceiver(uint8(inport))

	var pdp pcapdumperParameters
	flow.SetHandler(f1, pcapdumper, &pdp)

	// Send packets to control speed. One queue will be added automatically.
	flow.SetSender(f1, uint8(outport))

	flow.SystemStart()
}

type pcapdumperParameters struct {
	f *os.File
}

func (pd pcapdumperParameters) Copy() interface{} {
	filename := fmt.Sprintf("dumped%d.pcap", cloneNumber)
	f, err := os.Create(filename)
	if err != nil {
		fmt.Println("Cannot create file: ", err)
		os.Exit(0)
	}
	cloneNumber++
	packet.WritePcapGlobalHdr(f)
	pdp := pcapdumperParameters{f: f}
	return pdp
}

func (pd pcapdumperParameters) Delete() {
	pd.f.Close()
}

func pcapdumper(currentPacket *packet.Packet, context flow.UserContext) {
	pd := context.(pcapdumperParameters)
	currentPacket.WritePcapOnePacket(pd.f)
}
