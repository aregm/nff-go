// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var (
	outport uint
	inport  uint

	cloneNumber uint
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	flag.UintVar(&outport, "outport", 1, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.Parse()

	// Initialize YANFF library at 10 available cores
	config := flow.Config{
		CPUList: "0-9",
	}
	CheckFatal(flow.SystemInit(&config))

	// Receive packets from zero port. One queue will be added automatically.
	f1, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)

	var pdp pcapdumperParameters
	CheckFatal(flow.SetHandler(f1, pcapdumper, &pdp))

	// Send packets to control speed. One queue will be added automatically.
	CheckFatal(flow.SetSender(f1, uint8(outport)))

	CheckFatal(flow.SystemStart())
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
	if err := packet.WritePcapGlobalHdr(f); err != nil {
		log.Fatal(err)
	}
	pdp := pcapdumperParameters{f: f}
	return pdp
}

func (pd pcapdumperParameters) Delete() {
	pd.f.Close()
}

func pcapdumper(currentPacket *packet.Packet, context flow.UserContext) {
	pd := context.(pcapdumperParameters)
	if err := currentPacket.WritePcapOnePacket(pd.f); err != nil {
		log.Fatal(err)
	}
}
