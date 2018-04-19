// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"os"
	"sync/atomic"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var totalPackets int64
var count int64
var payloadSize uint

func main() {
	flag.Int64Var(&totalPackets, "totalPackets", 1234, "Number of packets to send")
	packetSize := *flag.Uint("packetSize", 128, "Size of generated packet")
	outport := uint16(*flag.Uint("outport", 0, "port for sender"))
	flag.Parse()

	// Total packet size is 14+20+20+payload_size+4(crc)
	hdrsSize := uint(14 + 20 + 20 + 4)
	payloadSize = packetSize - hdrsSize

	// Initialize NFF-GO library at 16 cores by default
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.CheckFatal(flow.SystemInit(&config))

	// With generator all packets are sent.
	f1 := flow.SetGenerator(generatePacket, nil)

	// With fast generator sent only multiple of burst-size.
	// f1 := flow.SetFastGenerator(generatePacket, 100, nil)
	f2, err := flow.SetPartitioner(f1, 350, 350)
	flow.CheckFatal(err)

	// Send all generated packets to the output
	flow.CheckFatal(flow.SetSender(f1, outport))
	flow.CheckFatal(flow.SetSender(f2, outport))

	flow.CheckFatal(flow.SystemStart())
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
