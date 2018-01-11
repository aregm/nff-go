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

// test-merge-part1:
// This part of test generates packets on ports 0 and 1, receives packets
// on 0 port. Packets generated on 0 port has IPv4 source addr ipv4addr1,
// and those generated on 1 port has ipv4 source addr ipv4addr2. For each packet
// sender calculates IPv4 and UDP checksums and verify it on packet receive.
// When packet is received, hash is recomputed and checked if it is equal to value
// in the packet. Test also calculates sent/received ratios, number of broken
// packets and prints it when a predefined number of packets is received.
//
// test-merge-part2:
// This part of test receives packets on 0 and 1 ports, merges flows
// and send result flow to 0 port.

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
	recvPackets       uint64
	brokenPackets     uint64

	// Usually when writing multibyte fields to packet, we should make
	// sure that byte order in packet buffer is correct and swap bytes if needed.
	// Here for testing purposes we use addresses with bytes swapped by hand.
	ipv4addr1 uint32 = 0x0100007f // 127.0.0.1
	ipv4addr2 uint32 = 0x05090980 // 128.9.9.5

	testDoneEvent *sync.Cond
	progStart     time.Time

	// T second timeout is used to let generator reach required speed
	// During timeout packets are skipped and not counted
	T = 10 * time.Second

	outport1 uint
	outport2 uint
	inport   uint

	fixMACAddrs1 func(*packet.Packet, flow.UserContext)
	fixMACAddrs2 func(*packet.Packet, flow.UserContext)
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
	flag.Uint64Var(&speed, "speed", speed, "speed of 1 and 2 generators, Pkts/s")
	flag.UintVar(&outport1, "outport1", 0, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.Uint64Var(&totalPackets, "number", totalPackets, "total number of packets to receive by test")
	flag.DurationVar(&T, "timeout", T, "test start delay, needed to stabilize speed. Packets sent during timeout do not affect test result")
	configFile := flag.String("config", "", "Specify json config file name (mandatory for VM)")
	target := flag.String("target", "", "Target host name from config file (mandatory for VM)")
	flag.Parse()

	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))
	stabilityCommon.InitCommonState(*configFile, *target)
	fixMACAddrs1 = stabilityCommon.ModifyPacket[outport1].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs2 = stabilityCommon.ModifyPacket[outport2].(func(*packet.Packet, flow.UserContext))

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	firstFlow, err := flow.SetGenerator(generatePacketGroup1, speed, nil)
	CheckFatal(err)
	CheckFatal(flow.SetSender(firstFlow, uint8(outport1)))

	// Create second packet flow
	secondFlow, err := flow.SetGenerator(generatePacketGroup2, speed, nil)
	CheckFatal(err)
	CheckFatal(flow.SetSender(secondFlow, uint8(outport2)))

	// Create receiving flow and set a checking function for it
	inputFlow, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)

	CheckFatal(flow.SetHandler(inputFlow, checkPackets, nil))
	CheckFatal(flow.SetStopper(inputFlow))

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
	// Proportions of 1 and 2 packet in received flow
	p1 := int(recv1 * 100 / received)
	p2 := int(recv2 * 100 / received)
	broken := atomic.LoadUint64(&brokenPackets)

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")
	println("Group1 ratio =", recv1*100/sent1, "%")
	println("Group2 ratio =", recv2*100/sent2, "%")

	println("Group1 proportion in received flow =", p1, "%")
	println("Group2 proportion in received flow =", p2, "%")

	println("Broken = ", broken, "packets")

	// Test is passed, if p1 and p2 do not differ too much: |p1-p2| < 4%
	// and enough packets received back
	if (p1-p2 < 4 || p2-p1 < 4) && received*100/sent > passedLimit {
		println("TEST PASSED")
	} else {
		println("TEST FAILED")
	}
}

func generatePacketGroup1(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		log.Fatal("Failed to create new packet")
	}
	if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
		log.Fatal("Failed to init empty packet")
	}
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	ipv4.SrcAddr = ipv4addr1
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))

	fixMACAddrs1(pkt, context)

	// We do not consider the start time of the system in this test
	if time.Since(progStart) < T {
		return
	}

	atomic.AddUint64(&sentPacketsGroup1, 1)
}

func generatePacketGroup2(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		log.Fatal("Failed to create new packet")
	}
	if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
		log.Fatal("Failed to init empty packet")
	}
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	ipv4.SrcAddr = ipv4addr2
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))

	fixMACAddrs2(pkt, context)

	// We do not consider the start time of the system in this test
	if time.Since(progStart) < T {
		return
	}

	atomic.AddUint64(&sentPacketsGroup2, 1)
}

// Count and check packets in received flow
func checkPackets(pkt *packet.Packet, context flow.UserContext) {
	if time.Since(progStart) < T {
		return
	}
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	pkt.ParseData()

	recvCount := atomic.AddUint64(&recvPackets, 1)

	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	recvIPv4Cksum := packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	recvUDPCksum := packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))

	if recvIPv4Cksum != ipv4.HdrChecksum || recvUDPCksum != udp.DgramCksum {
		// Packet is broken
		atomic.AddUint64(&brokenPackets, 1)
		return
	}
	if ipv4.SrcAddr == ipv4addr1 {
		atomic.AddUint64(&recvPacketsGroup1, 1)
	} else if ipv4.SrcAddr == ipv4addr2 {
		atomic.AddUint64(&recvPacketsGroup2, 1)
	} else {
		println("Packet Ipv4 src addr does not match addr1 or addr2")
		println("TEST FAILED")
	}

	if recvCount >= totalPackets {
		testDoneEvent.Signal()
	}
}
