// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/md5"
	"flag"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"sync"
	"sync/atomic"
	"unsafe"
)

// test-split-part1: sends packts to 0 port, receives from 0 and 1 ports.
// This part of test generates packet flow, containing on 20% group1 and 80% group2 packets.
// group1 and group2 has UDP dst ports dstPort1, dstPort2 respectively. For each packet
// sender calculates md5 hash sum from all headers, write it to packet.Data and check it
// on packet receive.
// This part of test receive packets on 0 and 1 ports.
// Expects to get approximately 20% on 0 port and 80% on 1 port.
// Test also calculates sent/received ratios, number of broken packets and prints it when
// a predefined number of packets is received.
//
// test-split-part2:
// This part of test receives packets on 0 port, split input flow according to rules
// in test-split.conf into 3 flows. 0 flow is dropped. 1,2 flows are sent back to
// 0 and 1 ports respectively.

const (
	totalPackets = 100000000

	// Test is PASSED if portion of packet number in receive flow
	// belongs to interval [LOW; HIGH]
	eps   = 4
	high1 = 20 + eps
	low1  = 20 - eps
	high2 = 80 + eps
	low2  = 80 - eps
)

var (
	// Payload is 16 byte md5 hash sum of headers
	payloadSize uint   = 454
	speed       uint64 = 6000000 // for 512 pkt ~ 25Gb/s
	passedLimit uint64 = 85

	sentPacketsGroup1 uint64
	sentPacketsGroup2 uint64

	recvPacketsGroup1 uint64
	recvPacketsGroup2 uint64

	count         uint64
	recvPackets   uint64
	brokenPackets uint64

	dstPort1 uint16 = 111
	dstPort2 uint16 = 222

	testDoneEvent *sync.Cond

	outport uint
	inport1 uint
	inport2 uint
	inport3 uint
)

func main() {
	flag.Uint64Var(&passedLimit, "passedLimit", passedLimit, "received/sent minimum ratio to pass test")
	flag.Uint64Var(&speed, "speed", speed, "speed of generator, Pkts/s")
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport1, "inport1", 0, "port for 1st receiver")
	flag.UintVar(&inport2, "inport2", 1, "port for 2nd receiver")
	flag.Parse()

	// Init YANFF system at 20 available cores.
	config := flow.Config{
		CPUCoresNumber: 20,
	}
	flow.SystemInit(&config)

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	// Create first packet flow
	outputFlow := flow.SetGenerator(generatePacket, speed, nil)
	flow.SetSender(outputFlow, uint8(outport))

	// Create receiving flows and set a checking function for it
	inputFlow1 := flow.SetReceiver(uint8(inport1))
	flow.SetHandler(inputFlow1, checkInputFlow1, nil)

	inputFlow2 := flow.SetReceiver(uint8(inport2))
	flow.SetHandler(inputFlow2, checkInputFlow2, nil)

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
	sent := sent1 + sent2

	recv1 := atomic.LoadUint64(&recvPacketsGroup1)
	recv2 := atomic.LoadUint64(&recvPacketsGroup2)
	received := recv1 + recv2

	var p1 int
	var p2 int
	if received != 0 {
		p1 = int(recv1 * 100 / received)
		p2 = int(recv2 * 100 / received)
	}
	broken := atomic.LoadUint64(&brokenPackets)

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")
	println("Ratio =", received*100/sent, "%")
	println("Group1 ratio =", recv1*100/sent1, "%")
	println("Group2 ratio =", recv2*100/sent2, "%")

	println("Group1 proportion of packets received on", inport1, "port =", p1, "%")
	println("Group2 proportion of packets received on", inport2, "port =", p2, "%")

	println("Broken = ", broken, "packets")

	// Test is passed, if each of p1 ~ 20% and p2 ~80%
	// and if total receive/send rate is high
	if p1 <= high1 && p2 <= high2 && p1 >= low1 && p2 >= low2 && received*100/sent > passedLimit {
		println("TEST PASSED")
	} else {
		println("TEST FAILED")
	}

}

// Function to use in generator
func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	atomic.AddUint64(&count, 1)

	if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
		panic("Failed to init empty packet")
	}

	if count%5 == 0 {
		(*packet.UDPHdr)(pkt.L4).DstPort = packet.SwapBytesUint16(dstPort1)
		atomic.AddUint64(&sentPacketsGroup1, 1)
	} else {
		(*packet.UDPHdr)(pkt.L4).DstPort = packet.SwapBytesUint16(dstPort2)
		atomic.AddUint64(&sentPacketsGroup2, 1)
	}

	// Extract headers of packet
	headerSize := uintptr(pkt.Data) - pkt.Start()
	hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Start()))[0:headerSize]
	ptr := (*packetData)(pkt.Data)
	ptr.HdrsMD5 = md5.Sum(hdrs)
}

func checkInputFlow1(pkt *packet.Packet, context flow.UserContext) {
	recvCount := atomic.AddUint64(&recvPackets, 1)

	offset := pkt.ParseData()
	if offset < 0 {
		println("ParseData returned negative value", offset)
		// Some received packets are not generated by this example
		// They cannot be parsed due to unknown protocols, skip them
	} else {
		ptr := (*packetData)(pkt.Data)

		// Recompute hash to check how many packets are valid
		headerSize := uintptr(pkt.Data) - pkt.Start()
		hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Start()))[0:headerSize]
		hash := md5.Sum(hdrs)

		if hash != ptr.HdrsMD5 {
			// Packet is broken
			atomic.AddUint64(&brokenPackets, 1)
			return
		}
		if (*packet.UDPHdr)(pkt.L4).DstPort == packet.SwapBytesUint16(dstPort1) {
			atomic.AddUint64(&recvPacketsGroup1, 1)
		}
	}
	if recvCount >= totalPackets {
		testDoneEvent.Signal()
	}
}

func checkInputFlow2(pkt *packet.Packet, context flow.UserContext) {
	recvCount := atomic.AddUint64(&recvPackets, 1)

	offset := pkt.ParseData()
	if offset < 0 {
		println("ParseData returned negative value", offset)
		// Some received packets are not generated by this example
		// They cannot be parsed due to unknown protocols, skip them
	} else {
		ptr := (*packetData)(pkt.Data)

		// Recompute hash to check how many packets are valid
		headerSize := uintptr(pkt.Data) - pkt.Start()
		hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Start()))[0:headerSize]
		hash := md5.Sum(hdrs)

		if hash != ptr.HdrsMD5 {
			// Packet is broken
			atomic.AddUint64(&brokenPackets, 1)
			return
		}
		if (*packet.UDPHdr)(pkt.L4).DstPort == packet.SwapBytesUint16(dstPort2) {
			atomic.AddUint64(&recvPacketsGroup2, 1)
		}
	}
	if recvCount >= totalPackets {
		testDoneEvent.Signal()
	}
}

type packetData struct {
	HdrsMD5 [16]byte
}
