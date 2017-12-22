// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"github.com/intel-go/yanff/test/stability/stabilityCommon"
)

// test-split-part1: sends packts to 0 port, receives from 0 and 1 ports.
// This part of test generates packet flow, containing on 20% group1 and 80% group2 packets.
// group1 and group2 has UDP dst ports dstPort1, dstPort2 respectively. For each packet
// sender calculates IPv4 and UDP checksums and verify it on packet receive.
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
	// Test is PASSED if portion of packet number in receive flow
	// belongs to interval [LOW; HIGH]
	eps   = 4
	high1 = 20 + eps
	low1  = 20 - eps
	high2 = 80 + eps
	low2  = 80 - eps
)

var (
	totalPackets uint64 = 10000000
	// Payload is 16 byte md5 hash sum of headers
	payloadSize uint   = 16
	speed       uint64 = 1000000
	passedLimit uint64 = 85

	sentPacketsGroup1 uint64
	sentPacketsGroup2 uint64

	recvPacketsGroup1 uint64
	recvPacketsGroup2 uint64

	count          uint64
	countFromStart uint64
	recvPackets    uint64
	brokenPackets  uint64

	dstPort1 uint16 = 111
	dstPort2 uint16 = 222

	testDoneEvent *sync.Cond
	progStart     time.Time

	// T second timeout is used to let generator reach required speed
	// During timeout packets are skipped and not counted
	T = 10 * time.Second

	outport uint
	inport1 uint
	inport2 uint

	fixMACAddrs func(*packet.Packet, flow.UserContext)
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	flag.Uint64Var(&passedLimit, "passedLimit", passedLimit, "received/sent minimum ratio to pass test")
	flag.Uint64Var(&speed, "speed", speed, "speed of generator, Pkts/s")
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport1, "inport1", 0, "port for 1st receiver")
	flag.UintVar(&inport2, "inport2", 1, "port for 2nd receiver")
	flag.Uint64Var(&totalPackets, "number", totalPackets, "total number of packets to receive by test")
	flag.DurationVar(&T, "timeout", T, "test start timeout. Packets sent during timeout do not affect test result")
	configFile := flag.String("config", "", "Specify json config file name (mandatory for VM)")
	target := flag.String("target", "", "Target host name from config file (mandatory for VM)")
	flag.Parse()

	// Init YANFF system at 20 available cores.
	config := flow.Config{
		CPUList: "0-19",
	}
	CheckFatal(flow.SystemInit(&config))
	stabilityCommon.InitCommonState(*configFile, *target)
	fixMACAddrs = stabilityCommon.ModifyPacket[outport].(func(*packet.Packet, flow.UserContext))

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	// Create first packet flow
	outputFlow, err := flow.SetGenerator(generatePacket, speed, nil)
	CheckFatal(err)
	CheckFatal(flow.SetSender(outputFlow, uint8(outport)))

	// Create receiving flows and set a checking function for it
	inputFlow1, err := flow.SetReceiver(uint8(inport1))
	CheckFatal(err)
	CheckFatal(flow.SetHandler(inputFlow1, checkInputFlow1, nil))

	inputFlow2, err := flow.SetReceiver(uint8(inport2))
	CheckFatal(err)
	CheckFatal(flow.SetHandler(inputFlow2, checkInputFlow2, nil))

	CheckFatal(flow.SetStopper(inputFlow1))
	CheckFatal(flow.SetStopper(inputFlow2))

	// Start pipeline
	go func() {
		CheckFatal(flow.SystemStart())
	}()
	progStart = time.Now()

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
		log.Fatal("Failed to create new packet")
	}
	if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
		log.Fatal("Failed to init empty packet")
	}
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	// We do not consider the start time of the system in this test
	if time.Since(progStart) < T {
		return
	}
	if count%5 == 0 {
		udp.DstPort = packet.SwapBytesUint16(dstPort1)
		atomic.AddUint64(&sentPacketsGroup1, 1)
	} else {
		udp.DstPort = packet.SwapBytesUint16(dstPort2)
		atomic.AddUint64(&sentPacketsGroup2, 1)
	}
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))
	fixMACAddrs(pkt, context)
	atomic.AddUint64(&count, 1)
}

func checkInputFlow1(pkt *packet.Packet, context flow.UserContext) {
	if time.Since(progStart) < T {
		return
	}
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	recvCount := atomic.AddUint64(&recvPackets, 1)

	pkt.ParseData()
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	recvIPv4Cksum := packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	recvUDPCksum := packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))
	if recvIPv4Cksum != ipv4.HdrChecksum || recvUDPCksum != udp.DgramCksum {
		// Packet is broken
		atomic.AddUint64(&brokenPackets, 1)
		return
	}
	if udp.DstPort != packet.SwapBytesUint16(dstPort1) {
		println("Unexpected packet in inputFlow1")
		println("TEST FAILED")
		return
	}
	atomic.AddUint64(&recvPacketsGroup1, 1)
	if recvCount >= totalPackets {
		testDoneEvent.Signal()
	}
}

func checkInputFlow2(pkt *packet.Packet, context flow.UserContext) {
	if time.Since(progStart) < T {
		return
	}
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	recvCount := atomic.AddUint64(&recvPackets, 1)

	pkt.ParseData()
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	recvIPv4Cksum := packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	recvUDPCksum := packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))
	if recvIPv4Cksum != ipv4.HdrChecksum || recvUDPCksum != udp.DgramCksum {
		// Packet is broken
		atomic.AddUint64(&brokenPackets, 1)
		return
	}
	if udp.DstPort != packet.SwapBytesUint16(dstPort2) {
		println("Unexpected packet in inputFlow2")
		println("TEST FAILED")
		return
	}
	atomic.AddUint64(&recvPacketsGroup2, 1)
	if recvCount >= totalPackets {
		testDoneEvent.Signal()
	}
}
