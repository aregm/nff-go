// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"time"
)

// You need to enable memory jumbo for maxPacketSegment more than 2014.
// Explanation: internal packet buffers are 2048 bytes, first packet will have
// ethernet and ipv4 headers = 14 + 2 = 34 bytes.
// Buffer will overflows if maxPacketSegment > 2048 - 34 = 2014 bytes

// Note: usage of 1484 < maxPacketSegment < 2014 without memory jumbo can work
// on some NICs, but is treated as underfined behaviour
// Explanation: in this situation packet will be fit in internal buffers
// however packet will be more than 1518 bytes - Ethernet max non-jumbo frame
const maxPacketSegment = 1484

// You need to enale chained jumbo for requiredPacketLength > maxPacketSegment
// Explanation: if required length is more than segment length packet will consist of
// several chained segments. You should enable chained jumbo to correctly handle them

// Note: usage of maxPacketSegment > 2014 and also requiredPacketLength > maxPacketSegment
// is forbidden. If you decicde to chain packets you shouldn't chain non-standart packets
// Explanation: in this situation you will need to enable both
// memory and chained jumbo and this is forbidden
const requiredPacketLength = 7000

func main() {
	chained := flag.Bool("chained", false, "enable chained jumbo")
	memory := flag.Bool("memory", false, "enalbe memory jumbo")
	flag.Parse()

	// Initialize NFF-GO library at 10 available cores
	config := flow.Config{
		ChainedJumbo: *chained,
		MemoryJumbo:  *memory,
	}

	flow.CheckFatal(flow.SystemInit(&config))

	generated := flow.SetGenerator(generate, nil)
	flow.SetHandler(generated, dump, nil)
	flow.SetSender(generated, 0)

	received, _ := flow.SetReceiver(0)
	flow.SetHandler(received, dump, nil)
	flow.SetStopper(received)
	flow.SystemStart()
}

func generate(pkt *packet.Packet, context flow.UserContext) {
	remain := requiredPacketLength
	c := 0
	diff, remain := m(maxPacketSegment, remain)
	if packet.InitEmptyIPv4Packet(pkt, diff) == false {
		fmt.Printf("maxPacketSegment %d is more than 2014 bytes without enabling memory jumbo\n", maxPacketSegment)
		time.Sleep(5 * time.Second)
		return
	}
	pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	for i := 0; i < maxPacketSegment; i++ {
		(*(*[maxPacketSegment]byte)(pkt.Data))[i] = byte(c % 10)
		c++
	}
	for remain != 0 {
		diff, remain = m(maxPacketSegment, remain)
		pkt = packet.InitNextPacket(diff, pkt)
		for i := 0; i < maxPacketSegment; i++ {
			(*(*[maxPacketSegment]byte)(pkt.Data))[i] = byte(c % 10)
			c++
		}
	}
	time.Sleep(1 * time.Second)
}

func m(max int, remain int) (uint, int) {
	if remain > max {
		return uint(max), remain - max
	} else {
		return uint(remain), 0
	}
}

func dump(currentPacket *packet.Packet, context flow.UserContext) {
	fmt.Println("NEW PACKET")
	fmt.Printf("BLOCK\n%x\nEND_BLOCK\n", currentPacket.GetRawPacketBytes())
	for currentPacket.Next != nil {
		currentPacket = currentPacket.Next
		fmt.Printf("BLOCK\n%x\nEND_BLOCK\n", currentPacket.GetRawPacketBytes())
	}
	fmt.Println("END PACKET")
}
