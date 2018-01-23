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

// test-partition-part1: sends packets to 0 port, receives from 0 and 1 ports.
// This part of test generates empty packets and send to 0 port. For each packet sender
// calculates IPv4 and UDP checksums and verify it on packet receive.
// This part of test expects to get approximately 90% of packet on 0 port and ~10% packets on 1 port.
// Test also calculates number of broken packets and prints it when
// a predefined number of packets is received.
//
// test-partition-part2:
// This part of test receives packets on 0 port, use partition function to create second flow.
// First 1000 received packets stay in this flow, next 100 go to new flow, and so on.

const (
	// Test expects to receive ~90% of packets on 0 port and ~10% on 1 port
	// Test is PASSSED, if p1 is in [low1;high1] and p2 in [low2;high2]
	eps   = 3
	high1 = 90 + eps
	low1  = 90 - eps
	high2 = 10 + eps
	low2  = 10 - eps
)

var (
	totalPackets uint64 = 10000000
	// Payload is 16 byte md5 hash sum of headers
	payloadSize uint   = 16
	speed       uint64 = 1000000
	passedLimit uint64 = 85

	sent          uint64
	recvPackets   uint64
	recvCount1    uint64
	recvCount2    uint64
	brokenPackets uint64
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
	flag.DurationVar(&T, "timeout", T, "test start delay, needed to stabilize speed. Packets sent during timeout do not affect test result")
	configFile := flag.String("config", "", "Specify json config file name (mandatory for VM)")
	target := flag.String("target", "", "Target host name from config file (mandatory for VM)")
	flag.Parse()

	// Init YANFF system at 16 available cores
	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))
	stabilityCommon.InitCommonState(*configFile, *target)
	fixMACAddrs = stabilityCommon.ModifyPacket[outport].(func(*packet.Packet, flow.UserContext))

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	// Create output packet flow
	outputFlow, err := flow.SetFastGenerator(generatePacket, speed, nil)
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
	recv1 := atomic.LoadUint64(&recvCount1)
	recv2 := atomic.LoadUint64(&recvCount2)
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

	println("Proportion of packets received on", inport1, "port ", p1, "%")
	println("Proportion of packets received on", inport2, "port ", p2, "%")

	println("Broken = ", broken, "packets")

	if p1 <= high1 && p2 <= high2 && p1 >= low1 && p2 >= low2 && received*100/sent > passedLimit {
		println("TEST PASSED")
	} else {
		println("TEST FAILED")
	}

}

// Generate packets
func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		log.Fatal("Failed to create new packet")
	}
	if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
		log.Fatal("Failed to init empty packet")
	}
	// We do not consider the start time of the system in this test
	if time.Since(progStart) < T {
		return
	}
	fixMACAddrs(pkt, context)

	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))

	atomic.AddUint64(&sent, 1)
}

func checkInputFlow1(pkt *packet.Packet, context flow.UserContext) {
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
	atomic.AddUint64(&recvCount1, 1)
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
	atomic.AddUint64(&recvCount2, 1)
	if recvCount >= totalPackets {
		testDoneEvent.Signal()
	}
}
