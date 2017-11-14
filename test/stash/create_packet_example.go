// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"flag"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var firstFlow *flow.Flow
var buffer []byte

func main() {
	// By default this example generates 128-byte empty packets with
	// InitEmptyIPv4TCPPacket() and set Ethernet destination address.
	// If flag enabled, generates packets with GeneratePacketFromByte() from raw buffer.
	enablePacketFromByte := flag.Bool("pfb", false, "enables generating packets with GeneratePacketFromByte() from raw buffer. Otherwise, by default empty 128-byte packets are generated")
	flag.Parse()

	// Initialize YANFF library at 16 available cores
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.SystemInit(&config)

	// Create packets with speed at least 1000 packets/s
	if *enablePacketFromByte == false {
		firstFlow = flow.SetGenerator(generatePacket, 1000, nil)
	} else {
		buffer, _ = hex.DecodeString("00112233445501112131415108004500002ebffd00000406747a7f0000018009090504d2162e123456781234569050102000ffe60000")
		firstFlow = flow.SetGenerator(generatePacketFromByte, 1000, nil)
	}
	// Send all generated packets to the output
	flow.SetSender(firstFlow, 1)
	flow.SystemStart()
}

func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	// Total packet size will be 14+20+20+70+4(crc)=128 bytes
	if packet.InitEmptyPacket(pkt, 70) == true {
		pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	}
}

func generatePacketFromByte(emptyPacket *packet.Packet, context flow.UserContext) {
	// Total packet size is 64 bytes
	packet.GeneratePacketFromByte(emptyPacket, buffer)
}
