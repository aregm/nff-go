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
	inFile  string
	outFile string

	outport  uint
	repcount int

	useReader bool
	useWriter bool
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	flag.StringVar(&inFile, "infile", "rw_example_in.pcap", "Input pcap file")
	flag.StringVar(&outFile, "outfile", "rw_example_out.pcap", "Output pcap file")

	flag.BoolVar(&useReader, "reader", false, "Enable Reader")
	flag.BoolVar(&useWriter, "writer", false, "Enable Writer")

	flag.IntVar(&repcount, "repcnt", 1, "Number of times for reader to read infile")
	flag.UintVar(&outport, "outport", 0, "Port for sender")
	flag.Parse()

	// Initialize YANFF library at 16 cores by default
	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))

	var f1 *flow.Flow
	if useReader {
		print("Enabled Read from file ", inFile, " and ")
		f1 = flow.SetReceiverFile(inFile, int32(repcount))
	} else {
		print("Enabled Generate and ")
		f1 = flow.SetGenerator(generatePacket, nil)
	}

	if useWriter {
		println("Write to file", outFile)
		CheckFatal(flow.SetSenderFile(f1, outFile))
	} else {
		println("Send to port", outport)
		CheckFatal(flow.SetSender(f1, uint8(outport)))
	}

	CheckFatal(flow.SystemStart())
}

func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	// Total packet size will be 14+20+20+70+4(crc)=128 bytes
	if packet.InitEmptyPacket(pkt, 70) == true {
		pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	}
}
