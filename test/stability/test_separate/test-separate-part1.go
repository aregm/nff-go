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
	"unsafe"
)

// test-separate-part1: sends packets to 0 port, receives from 0 and 1 ports.
// This part of test generates three packet flows (1st, 2nd and 3rd), merges them into one flow
// and send it to 0 port. Packets in original 1st, 2nd and 3rd flows has UDP destination addresses
// DSTPORT_1, DSTPORT_2, DSTPORT_3 respectively. For each packet sender calculates md5 hash sum
// from all headers, write it to packet.Data and check it on packet receive.
// This part of test receive packets on 0 and 1 ports. Expects to get ~33% of packets on 0 port
// (accepted) and ~66% on 1 port (rejected)
// Test also calculates number of broken packets and prints it when a predefined number
// of packets is received.
//
// test-separate-part2:
// This part of test receives packets on 0 port, separate input flow according to rules
// in test-separate-l3rules.conf into 2 flows. Accepted flow sent to 0 port, rejected - to 1 port.

const (
	TOTAL_PACKETS = 100000000
	options       = `{"cores": {"Value": 16, "Locked": false}}`

	// Test expects to receive 33% of packets on 0 port and 66% on 1 port
	// Test is PASSSED, if p1 is in [LOW1;HIGH1] and p2 in [LOW2;HIGH2]
	eps   = 2
	HIGH1 = 33 + eps
	LOW1  = 33 - eps
	HIGH2 = 66 + eps
	LOW2  = 66 - eps
)

var (
	// Payload is 16 byte md5 hash sum of headers
	PAYLOAD_SIZE uint = 16

	sentPacketsGroup1 uint64 = 0
	sentPacketsGroup2 uint64 = 0
	sentPacketsGroup3 uint64 = 0

	recvOnPort0 uint64 = 0
	recvOnPort1 uint64 = 0

	recvPackets   uint64 = 0
	brokenPackets uint64 = 0

	DSTPORT_1 uint16 = 111
	DSTPORT_2 uint16 = 222
	DSTPORT_3 uint16 = 333

	testDoneEvent *sync.Cond = nil
)

func main() {
	// Init YANFF system at requested number of cores.
	flow.SystemInit(options)

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	// Create first packet flow
	flow1 := flow.SetGenerator(generatePacketGroup1, 100)
	flow2 := flow.SetGenerator(generatePacketGroup2, 100)
	flow3 := flow.SetGenerator(generatePacketGroup3, 100)

	outputFlow := flow.SetMerger(flow1, flow2, flow3)

	flow.SetSender(outputFlow, 0)

	// Create receiving flows and set a checking function for it
	inputFlow1 := flow.SetReceiver(0)
	flow.SetHandler(inputFlow1, checkPacketsOn0Port)

	inputFlow2 := flow.SetReceiver(1)
	flow.SetHandler(inputFlow2, checkPacketsOn1Port)

	flow.SetStopper(inputFlow1)
	flow.SetStopper(inputFlow2)

	// Start pipeline
	go flow.SystemStart()

	// Wait for enough packets to arrive
	testDoneEvent.L.Lock()
	testDoneEvent.Wait()
	testDoneEvent.L.Unlock()

	// Compose statistics
	sent1 := atomic.LoadUint64(&sentPacketsGroup1)
	sent2 := atomic.LoadUint64(&sentPacketsGroup2)
	sent3 := atomic.LoadUint64(&sentPacketsGroup3)
	sent := sent1 + sent2 + sent3

	recv0 := atomic.LoadUint64(&recvOnPort0)
	recv1 := atomic.LoadUint64(&recvOnPort1)
	received := recv0 + recv1

	var p1 int
	var p2 int
	if received != 0 {
		p1 = int(recv0 * 100 / received)
		p2 = int(recv1 * 100 / received)
	}
	broken := atomic.LoadUint64(&brokenPackets)

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")

	println("On port 0 received=", recv0, "pkts")
	println("On port 1 received=", recv1, "pkts")

	println("Proportion of packets received on 0 port ", p1, "%")
	println("Proportion of packets received on 1 port ", p2, "%")

	println("Broken = ", broken, "packets")

	// Test is PASSSED, if p1 is ~33% and p2 is ~66%
	if p1 <= HIGH1 && p2 <= HIGH2 && p1 >= LOW1 && p2 >= LOW2 {
		println("TEST PASSED")
	} else {
		println("TEST FAILED")
	}

}

// Generate packets of 1 group
func generatePacketGroup1(pkt *packet.Packet) {
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

	atomic.AddUint64(&sentPacketsGroup1, 1)
}

// Generate packets of 2 group
func generatePacketGroup2(pkt *packet.Packet) {
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

	atomic.AddUint64(&sentPacketsGroup2, 1)
}

// Generate packets of 3 group
func generatePacketGroup3(pkt *packet.Packet) {
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

	atomic.AddUint64(&sentPacketsGroup3, 1)
}

// Count and check packets received on 0 port
func checkPacketsOn0Port(pkt *packet.Packet) {
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
	if recvCount >= TOTAL_PACKETS {
		testDoneEvent.Signal()
	}
}

// Count and check packets received on 1 port
func checkPacketsOn1Port(pkt *packet.Packet) {
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
		atomic.AddUint64(&recvOnPort1, 1)
	}
	if recvCount >= TOTAL_PACKETS {
		testDoneEvent.Signal()
	}
}

type PacketData struct {
	HdrsMD5 [16]byte
}
