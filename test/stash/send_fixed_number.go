// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"os"
	"sync/atomic"
)

var totalPackets int64
var packetSize uint
var outport uint
var count int64

// Total packet size is 14+20+20+payload_size+4(crc)
var payloadSize uint
var hdrsSize uint = 14 + 20 + 20 + 4

func main() {
	flag.Int64Var(&totalPackets, "totalPackets", 1234, "Number of packets to send")
	flag.UintVar(&packetSize, "packetSize", 128, "Size of generated packet")
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.Parse()

	payloadSize = packetSize - hdrsSize

	// Initialize YANFF library at 16 cores by default
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.SystemInit(&config)

	// With generateOne all packets are sent.
	f1 := flow.SetGenerator(generatePacket, 0, nil)
	// With generatePerf sent only multiple of burst-size.
	// f1 := flow.SetGenerator(generatePacket, 100, nil)
	f2 := flow.SetPartitioner(f1, 350, 350)

	// Send all generated packets to the output
	flow.SetSender(f1, uint8(outport))
	flow.SetSender(f2, uint8(outport))

	flow.SystemStart()
}

func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	sent := atomic.LoadInt64(&count)
	if packet.InitEmptyIPv4TCPPacket(pkt, payloadSize) == false {
		panic("Failed to init empty packet")
	}
	pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	if sent >= totalPackets {
		println("Sent ", sent, "number of packets")
		os.Exit(0)
	}
	atomic.AddInt64(&count, 1)
}
