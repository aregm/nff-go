// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/test/stability/stabilityCommon"
)

// Test with testScenario=1:
// sends packets to 0 port, receives from 0 and 1 ports.
// This part of test generates packets with UDP destination addresses
// dstPort1, dstPort2, dstPort3. For each packet sender
// calculates IPv4 and UDP checksums and verify it on packet receive.
// This part of test receive packets on 0 and 1 ports. Expects to get ~33% of packets on 0 port
// (accepted) and ~66% on 1 port (rejected)
// Test also calculates number of broken packets and prints it when a predefined number
// of packets is received.
//
// Test with testScenario=2:
// This part of test receives packets on 0 port, separate input flow according to rules
// in test-separate-l3rules.conf into 2 flows. Accepted flow sent to 0 port, rejected - to 1 port.
//
// Test with testScenario=0:
// all these actions are made in one pipeline without actual send and receive.

const (
	// Test expects to receive 33% of packets on 0 port and 66% on 1 port
	// Test is PASSSED, if p1 is in [low1;high1] and p2 in [low2;high2]
	eps   = 2
	high1 = 33 + eps
	low1  = 33 - eps
	high2 = 66 + eps
	low2  = 66 - eps
)

var (
	totalPackets uint64 = 10000000
	// Payload is 16 byte md5 hash sum of headers
	payloadSize uint   = 16
	speed       uint64 = 1000000
	passedLimit uint64 = 85

	recvCount1 uint64
	recvCount2 uint64

	count         uint64
	recvPackets   uint64
	brokenPackets uint64

	dstPort1 uint16 = 111
	dstPort2 uint16 = 222
	dstPort3 uint16 = 333

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

	l3Rules *packet.L3Rules
)

func main() {
	var testScenario uint
	flag.UintVar(&testScenario, "testScenario", 0, "1 to use 1st part scenario, 2 snd, 0 to use one-machine test")
	flag.Uint64Var(&passedLimit, "passedLimit", passedLimit, "received/sent minimum ratio to pass test")
	flag.Uint64Var(&speed, "speed", speed, "speed of generator, Pkts/s")
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

	fixMACAddrs = stabilityCommon.ModifyPacket[outport1].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs1 = stabilityCommon.ModifyPacket[outport1].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs2 = stabilityCommon.ModifyPacket[outport2].(func(*packet.Packet, flow.UserContext))

	if testScenario != 1 {
		var err error
		// Get splitting rules from access control file.
		l3Rules, err = packet.GetL3ACLFromORIG("test-separate-l3rules.conf")
		if err != nil { return err }
	}

	if testScenario == 2 {
		// Receive packets from 0 port
		flow1, err := flow.SetReceiver(uint8(inport1))
		if err != nil { return err }

		// Separate packet flow based on ACL.
		flow2, err := flow.SetSeparator(flow1, l3Separator, nil) // ~66% of packets should go to flow2, ~33% left in flow1
		if err != nil { return err }

		if err := flow.SetHandler(flow1, fixPackets1, nil); err != nil { return err }
		if err := flow.SetHandler(flow2, fixPackets2, nil); err != nil { return err }

		// Send each flow to corresponding port. Send queues will be added automatically.
		if err := flow.SetSender(flow1, uint8(outport1)); err != nil { return err }
		if err := flow.SetSender(flow2, uint8(outport2)); err != nil { return err }

		// Begin to process packets.
		if err := flow.SystemStart(); err != nil { return err }
	} else {
		var m sync.Mutex
		testDoneEvent = sync.NewCond(&m)

		// Create packet flow
		outputFlow, err := flow.SetFastGenerator(generatePacket, speed, nil)
		if err != nil { return err }
		var flow1, flow2 *flow.Flow
		if testScenario == 1 {
			if err := flow.SetSender(outputFlow, uint8(outport1)); err != nil { return err }

			// Create receiving flows and set a checking function for it
			flow1, err = flow.SetReceiver(uint8(inport1))
			if err != nil { return err }
			flow2, err = flow.SetReceiver(uint8(inport2))
			if err != nil { return err }
		} else {
			flow1 = outputFlow
			// Separate packet flow based on ACL.
			flow2, err = flow.SetSeparator(flow1, l3Separator, nil) // ~66% of packets should go to flow2, ~33% left in flow1
			if err != nil { return err }
			if err := flow.SetHandler(flow1, fixPackets1, nil); err != nil { return err }
			if err := flow.SetHandler(flow2, fixPackets2, nil); err != nil { return err }

		}
		if err := flow.SetHandler(flow1, checkInputFlow1, nil); err != nil { return err }
		if err := flow.SetHandler(flow2, checkInputFlow2, nil); err != nil { return err }

		if err := flow.SetStopper(flow1); err != nil { return err }
		if err := flow.SetStopper(flow2); err != nil { return err }

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
	sent := atomic.LoadUint64(&count)

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

	println("On port", inport1, "received=", recv1, "pkts")
	println("On port", inport2, "received=", recv2, "pkts")

	println("Proportion of packets received on", inport1, "port =", p1, "%")
	println("Proportion of packets received on", inport2, "port =", p2, "%")

	println("Broken = ", broken, "packets")

	// Test is PASSSED, if p1 is ~33% and p2 is ~66%
	if p1 <= high1 && p2 <= high2 && p1 >= low1 && p2 >= low2 && received*100/sent > passedLimit {
		println("TEST PASSED")
	} else {
		println("TEST FAILED")
	}

}

func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
		panic("Failed to init empty packet")
	}
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()

	// Generate packets of 3 groups
	if count%3 == 0 {
		udp.DstPort = packet.SwapBytesUint16(dstPort1)
	} else if count%3 == 1 {
		udp.DstPort = packet.SwapBytesUint16(dstPort2)
	} else {
		udp.DstPort = packet.SwapBytesUint16(dstPort3)
	}

	// We do not consider the start time of the system in this test
	if time.Since(progStart) < T {
		return
	}
	fixMACAddrs(pkt, context)

	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))

	atomic.AddUint64(&count, 1)
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
	if udp.DstPort != packet.SwapBytesUint16(dstPort1) {
		println("Unexpected packet in inputFlow1")
		println("TEST FAILED")
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
	if udp.DstPort != packet.SwapBytesUint16(dstPort2) && udp.DstPort != packet.SwapBytesUint16(dstPort3) {
		println("Unexpected packet in inputFlow2")
		println("TEST FAILED")
		return
	}
	atomic.AddUint64(&recvCount2, 1)
	if recvCount >= totalPackets {
		testDoneEvent.Signal()
	}
}

func l3Separator(pkt *packet.Packet, context flow.UserContext) bool {
	return pkt.L3ACLPermit(l3Rules)
}

func fixPackets1(pkt *packet.Packet, ctx flow.UserContext) {
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	fixMACAddrs1(pkt, ctx)
}

func fixPackets2(pkt *packet.Packet, ctx flow.UserContext) {
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	fixMACAddrs2(pkt, ctx)
}
