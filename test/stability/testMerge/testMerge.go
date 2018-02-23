// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/test/stability/stabilityCommon"
)

// Test with testScenario=1:
// This part of test generates packets on ports 0 and 1, receives packets
// on 0 port. Packets generated on 0 port has IPv4 source addr ipv4addr1,
// and those generated on 1 port has ipv4 source addr ipv4addr2. For each packet
// sender calculates IPv4 and UDP checksums and verify it on packet receive.
// When packet is received, hash is recomputed and checked if it is equal to value
// in the packet. Test also calculates sent/received ratios, number of broken
// packets and prints it when a predefined number of packets is received.
//
// Test with testScenario=2:
// This part of test receives packets on 0 and 1 ports, merges flows
// and send result flow to 0 port.
//
// Test with testScenario=0:
// all these actions are made in one pipeline without actual send and receive.

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
	inport1  uint
	inport2  uint
	dpdkLogLevel *string

	fixMACAddrs  func(*packet.Packet, flow.UserContext)
	fixMACAddrs1 func(*packet.Packet, flow.UserContext)
	fixMACAddrs2 func(*packet.Packet, flow.UserContext)
)

func main() {
	var testScenario uint
	flag.UintVar(&testScenario, "testScenario", 0, "1 to use 1st part scenario, 2 snd, 0 to use one-machine test")
	flag.Uint64Var(&passedLimit, "passedLimit", passedLimit, "received/sent minimum ratio to pass test")
	flag.Uint64Var(&speed, "speed", speed, "speed of 1 and 2 generators, Pkts/s")
	flag.UintVar(&outport1, "outport1", 0, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	flag.UintVar(&inport1, "inport1", 0, "port for 1st receiver")
	flag.UintVar(&inport2, "inport2", 1, "port for 2nd receiver")
	flag.Uint64Var(&totalPackets, "number", totalPackets, "total number of packets to receive by test")
	flag.DurationVar(&T, "timeout", T, "test start delay, needed to stabilize speed. Packets sent during timeout do not affect test result")
	configFile := flag.String("config", "", "Specify json config file name (mandatory for VM)")
	target := flag.String("target", "", "Target host name from config file (mandatory for VM)")
	dpdkLogLevel = flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()
	if err := executeTest(*configFile, *target, testScenario); err != nil {
		fmt.Printf("fail: %+v\n", err)
	}
}

func executeTest(configFile, target string, testScenario uint) error {
	if testScenario > 3 || testScenario < 0 {
		return errors.New("testScenario should be in interval [0, 3]")
	}
	// Init NFF-GO system
	config := flow.Config{
		DPDKArgs: []string{ *dpdkLogLevel },
	}
	if err := flow.SystemInit(&config); err != nil { return err }
	stabilityCommon.InitCommonState(configFile, target)

	fixMACAddrs1 = stabilityCommon.ModifyPacket[outport1].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs2 = stabilityCommon.ModifyPacket[outport2].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs = stabilityCommon.ModifyPacket[outport1].(func(*packet.Packet, flow.UserContext))

	if testScenario == 2 {
		// Receive packets from 0 and 1 ports
		inputFlow1, err := flow.SetReceiver(uint8(inport1))
		if err != nil { return err }
		inputFlow2, err := flow.SetReceiver(uint8(inport2))
		if err != nil { return err }

		outputFlow, err := flow.SetMerger(inputFlow1, inputFlow2)
		if err != nil { return err }
		if err := flow.SetHandler(outputFlow, fixPackets, nil); err != nil { return err }
		if err := flow.SetSender(outputFlow, uint8(outport1)); err != nil { return err }

		// Begin to process packets.
		if err := flow.SystemStart(); err != nil { return err }
	} else {
		var m sync.Mutex
		testDoneEvent = sync.NewCond(&m)

		firstFlow, err := flow.SetFastGenerator(generatePacketGroup1, speed, nil)
		if err != nil { return err }

		if testScenario == 1 {
			if err := flow.SetSender(firstFlow, uint8(outport1)); err != nil { return err }
		}

		// Create second packet flow
		secondFlow, err := flow.SetFastGenerator(generatePacketGroup2, speed, nil)
		if err != nil { return err }

		var finalFlow *flow.Flow
		if testScenario == 1 {
			if err := flow.SetSender(secondFlow, uint8(outport2)); err != nil { return err }
			// Create receiving flow and set a checking function for it
			finalFlow, err = flow.SetReceiver(uint8(inport1))
			if err != nil { return err }
		} else {
			finalFlow, err = flow.SetMerger(firstFlow, secondFlow)
			if err != nil { return err }
			if err := flow.SetHandler(finalFlow, fixPackets, nil); err != nil { return err }
		}

		if err := flow.SetHandler(finalFlow, checkPackets, nil); err != nil { return err }
		if err := flow.SetStopper(finalFlow); err != nil { return err }

		// Start pipeline
		go func() {
			err = flow.SystemStart()
		}()
		if err != nil { return err }
		progStart = time.Now()

		// Wait for enough packets to arrive
		testDoneEvent.L.Lock()
		testDoneEvent.Wait()
		testDoneEvent.L.Unlock()

		composeStatistics()
	}
	return nil
}

func composeStatistics() {
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

func fixPackets(pkt *packet.Packet, ctx flow.UserContext) {
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	fixMACAddrs(pkt, ctx)
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
