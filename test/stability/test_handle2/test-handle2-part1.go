// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/md5"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// test-handle2-part1: sends packets to 0 port, receives from 0 and 1 ports.
// This part of test generates three packet flows (1st, 2nd and 3rd), merges them into one flow
// and send it to 0 port. Packets in original 1st, 2nd and 3rd flows has UDP destination addresses
// DSTPORT_1, DSTPORT_2, DSTPORT_3 respectively. For each packet sender calculates md5 hash sum
// from all headers, write it to packet.Data and check it on packet receive.
// This part of test receive packets on 0 port, expects to receive ~33% of packets.
// Test also calculates number of broken packets and prints it when a predefined number
// of packets is received.
//
// test-handle2-part2:
// This part of test receives packets on 0 port, separate input flow according to rules
// in test-separate-l3rules.conf into 2 flows. Accepted flow sent to 0 port, rejected flow is stopped.

const (
	TOTAL_PACKETS = 100000000

	// Test expects to receive 33% of packets on 0 port.
	// Test is PASSSED, if p1 is in [LOW1;HIGH1]
	eps   = 5
	HIGH1 = 33 + eps
	LOW1  = 33 - eps
)

var (
	// Payload is 16 byte md5 hash sum of headers
	PAYLOAD_SIZE uint = 16
	d            uint = 10

	sentPacketsGroup1 uint64 = 0
	sentPacketsGroup2 uint64 = 0
	sentPacketsGroup3 uint64 = 0

	recvOnPort0 uint64 = 0

	recvPackets   uint64 = 0
	brokenPackets uint64 = 0

	DSTPORT_1 uint16 = 111
	DSTPORT_2 uint16 = 222
	DSTPORT_3 uint16 = 333

	testDoneEvent *sync.Cond = nil
)

func main() {
	// Init YANFF system at 16 available cores
	flow.SystemInit(16)

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	// Create first packet flow
	flow1 := flow.SetGenerator(generatePacketGroup1, 0, nil)
	flow2 := flow.SetGenerator(generatePacketGroup2, 0, nil)
	flow3 := flow.SetGenerator(generatePacketGroup3, 0, nil)

	outputFlow := flow.SetMerger(flow1, flow2, flow3)

	flow.SetSender(outputFlow, 0)

	// Create receiving flows and set a checking function for it
	inputFlow1 := flow.SetReceiver(0)
	flow.SetHandler(inputFlow1, checkPacketsOn0Port, nil)
	flow.SetStopper(inputFlow1)

	// Start pipeline
	go flow.SystemStart()

	// Wait for enough packets to arrive
	testDoneEvent.L.Lock()
	testDoneEvent.Wait()
	testDoneEvent.L.Unlock()

	// Compose statistics
	sent1 := sentPacketsGroup1
	sent2 := sentPacketsGroup2
	sent3 := sentPacketsGroup3
	sent := sent1 + sent2 + sent3

	received := atomic.LoadUint64(&recvOnPort0)

	var p int
	if sent != 0 {
		p = int(received * 100 / sent)
	}
	broken := atomic.LoadUint64(&brokenPackets)

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")
	println("Proportion of received packets ", p, "%")
	println("Broken = ", broken, "packets")

	// Test is PASSSED, if p is ~33%
	if p <= HIGH1 && p >= LOW1 {
		println("TEST PASSED")
	} else {
		println("TEST FAILED")
	}

}

// Generate packets of 1 group
func generatePacketGroup1(pkt *packet.Packet, context flow.UserContext) {
	packet.InitEmptyEtherIPv4UDPPacket(pkt, PAYLOAD_SIZE)
	if pkt == nil {
		panic("Failed to create new packet")
	}
	pkt.UDP.DstPort = packet.SwapBytesUint16(DSTPORT_1)

	// Extract headers of packet
	headerSize := uintptr(pkt.Data) - pkt.Unparsed
	hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Unparsed))[0:headerSize]
	ptr := (*PacketData)(pkt.Data)
	ptr.HdrsMD5 = md5.Sum(hdrs)

	sentPacketsGroup1++
	if sentPacketsGroup1 > TOTAL_PACKETS/3 {
		time.Sleep(time.Second * time.Duration(d))
		println("TEST FAILED")
	}
}

// Generate packets of 2 group
func generatePacketGroup2(pkt *packet.Packet, context flow.UserContext) {
	packet.InitEmptyEtherIPv4UDPPacket(pkt, PAYLOAD_SIZE)
	if pkt == nil {
		panic("Failed to create new packet")
	}
	pkt.UDP.DstPort = packet.SwapBytesUint16(DSTPORT_2)

	// Extract headers of packet
	headerSize := uintptr(pkt.Data) - pkt.Unparsed
	hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Unparsed))[0:headerSize]
	ptr := (*PacketData)(pkt.Data)
	ptr.HdrsMD5 = md5.Sum(hdrs)

	sentPacketsGroup2++
	if sentPacketsGroup1 > TOTAL_PACKETS/3 {
		time.Sleep(time.Second * time.Duration(d))
		println("TEST FAILED")
	}
}

// Generate packets of 3 group
func generatePacketGroup3(pkt *packet.Packet, context flow.UserContext) {
	packet.InitEmptyEtherIPv4UDPPacket(pkt, PAYLOAD_SIZE)
	if pkt == nil {
		panic("Failed to create new packet")
	}
	pkt.UDP.DstPort = packet.SwapBytesUint16(DSTPORT_3)

	// Extract headers of packet
	headerSize := uintptr(pkt.Data) - pkt.Unparsed
	hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Unparsed))[0:headerSize]
	ptr := (*PacketData)(pkt.Data)
	ptr.HdrsMD5 = md5.Sum(hdrs)

	sentPacketsGroup3++
	if sentPacketsGroup1 > TOTAL_PACKETS/3 {
		time.Sleep(time.Second * time.Duration(d))
		println("TEST FAILED")
	}
}

// Count and check packets received on 0 port
func checkPacketsOn0Port(pkt *packet.Packet, context flow.UserContext) {
	recvCount := atomic.AddUint64(&recvPackets, 1)

	offset := pkt.ParseL4Data()
	if offset < 0 {
		println("ParseL4Data returned negative value", offset)
		// Some received packets are not generated by this example
		// They cannot be parsed due to unknown protocols, skip them
	} else {
		ptr := (*PacketData)(pkt.Data)

		// Recompute hash to check how many packets are valid
		headerSize := uintptr(pkt.Data) - pkt.Unparsed
		hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Unparsed))[0:headerSize]
		hash := md5.Sum(hdrs)

		if hash != ptr.HdrsMD5 {
			// Packet is broken
			atomic.AddUint64(&brokenPackets, 1)
			return
		}
		atomic.AddUint64(&recvOnPort0, 1)
	}
	// TODO 80% of requested number of packets.
	if recvCount >= TOTAL_PACKETS/32*8 {
		testDoneEvent.Signal()
	}
}

type PacketData struct {
	HdrsMD5 [16]byte
}
