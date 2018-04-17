// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var (
	inFile  string
	outFile string

	outport  uint
	repcount int

	useReader bool
	useWriter bool
)

func main() {
	flag.StringVar(&inFile, "infile", "fileReadWriteIn.pcap", "Input pcap file")
	flag.StringVar(&outFile, "outfile", "fileReadWriteOut.pcap", "Output pcap file")

	flag.BoolVar(&useReader, "reader", false, "Enable Reader")
	flag.BoolVar(&useWriter, "writer", false, "Enable Writer")

	flag.IntVar(&repcount, "repcnt", 1, "Number of times for reader to read infile")
	flag.UintVar(&outport, "outport", 0, "Port for sender")
	flag.Parse()

	// Initialize NFF-GO library at 16 cores by default
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.CheckFatal(flow.SystemInit(&config))

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
		flow.CheckFatal(flow.SetSenderFile(f1, outFile))
	} else {
		println("Send to port", outport)
		flow.CheckFatal(flow.SetSender(f1, uint8(outport)))
	}

	flow.CheckFatal(flow.SystemStart())
}

func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	// Total packet size will be 14+20+20+70+4(crc)=128 bytes
	if packet.InitEmptyPacket(pkt, 70) == true {
		pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	}
}
