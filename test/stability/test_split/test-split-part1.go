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

// test-split-part1: sends packts to 0 port, receives from 1,2,3 ports.
// This part of test generates three packet flows (1st, 2nd and 3rd), merges them into one flow
// and send it to 0 port. Packets in original 1st, 2nd and 3rd flows has UDP destination addresses
// DSTPORT_1, DSTPORT_2, DSTPORT_3 respectively. For each packet sender calculates md5 hash sum
// from all headers, write it to packet.Data and check it on packet receive.
// This part of test receive packets on 1,2,3 ports. Expects to get approximately equal number
// of packets on each port.
// Test also calculates sent/received ratios, number of broken packets and prints it when
// a predefined number of packets is received.
//
// test-split-part2:
// This part of test receives packets on 0 port, split input flow according to rules
// in test-split.conf into 4 flows. 0 flow is dropped. 1,2,3 flows are sent back to
// 1,2,3 ports respectively.

const (
	TOTAL_PACKETS = 100000000
	options       = `{"cores": {"Value": 16, "Locked": false}}`

	// Proportion of each packet group among all received packets
	// from ports 1,2,3 should be nearly 33%.
	// Test is PASSED if portion belongs to interval [LOW; HIGH]
	eps  = 3
	HIGH = 33 + eps
	LOW  = 33 - eps
)

var (
	// Payload is 16 byte md5 hash sum of headers
	PAYLOAD_SIZE uint = 16

	sentPacketsGroup1 uint64 = 0
	sentPacketsGroup2 uint64 = 0
	sentPacketsGroup3 uint64 = 0

	recvPacketsGroup1 uint64 = 0
	recvPacketsGroup2 uint64 = 0
	recvPacketsGroup3 uint64 = 0

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
	inputFlow1 := flow.SetReceiver(1)
	flow.SetHandler(inputFlow1, checkPacketsOn1Port)

	inputFlow2 := flow.SetReceiver(2)
	flow.SetHandler(inputFlow2, checkPacketsOn2Port)

	inputFlow3 := flow.SetReceiver(3)
	flow.SetHandler(inputFlow3, checkPacketsOn3Port)

	flow.SetStopper(inputFlow1)
	flow.SetStopper(inputFlow2)
	flow.SetStopper(inputFlow3)

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

	recv1 := atomic.LoadUint64(&recvPacketsGroup1)
	recv2 := atomic.LoadUint64(&recvPacketsGroup2)
	recv3 := atomic.LoadUint64(&recvPacketsGroup3)
	received := recv1 + recv2 + recv3

	var p1 int
	var p2 int
	var p3 int
	if received != 0 {
		p1 = int(recv1 * 100 / received)
		p2 = int(recv2 * 100 / received)
		p3 = int(recv3 * 100 / received)
	}
	broken := atomic.LoadUint64(&brokenPackets)

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")
	println("Group1 ratio =", recv1*100/sent1, "%")
	println("Group2 ratio =", recv2*100/sent2, "%")
	println("Group3 ratio =", recv3*100/sent3, "%")

	println("Group1 proportion in received flow =", p1, "%")
	println("Group2 proportion in received flow =", p2, "%")
	println("Group3 proportion in received flow =", p3, "%")

	println("Broken = ", broken, "packets")

	// Test is passed, if each of p1, p2 and p3 is about 33%
	if p1 <= HIGH && p2 <= HIGH && p3 <= HIGH && p1 >= LOW && p2 >= LOW && p3 >= LOW {
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
		if pkt.UDP.DstPort == packet.SwapBytesUint16(DSTPORT_1) {
			atomic.AddUint64(&recvPacketsGroup1, 1)
		}
	}
	if recvCount >= TOTAL_PACKETS {
		testDoneEvent.Signal()
	}
}

// Count and check packets received on 2 port
func checkPacketsOn2Port(pkt *packet.Packet) {
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
		if pkt.UDP.DstPort == packet.SwapBytesUint16(DSTPORT_2) {
			atomic.AddUint64(&recvPacketsGroup2, 1)
		}
	}
	if recvCount >= TOTAL_PACKETS {
		testDoneEvent.Signal()
	}
}

// Count and check packets received on 2 port
func checkPacketsOn3Port(pkt *packet.Packet) {
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
		if pkt.UDP.DstPort == packet.SwapBytesUint16(DSTPORT_3) {
			atomic.AddUint64(&recvPacketsGroup3, 1)
		}
	}
	if recvCount >= TOTAL_PACKETS {
		testDoneEvent.Signal()
	}
}

type PacketData struct {
	HdrsMD5 [16]byte
}
