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
// sends packts to 0 port, receives from 0 and 1 ports.
// This part of test generates packet flow, containing on 20% group1 and 80% group2 packets.
// group1 and group2 has UDP dst ports dstPort1, dstPort2 respectively. For each packet
// sender calculates IPv4 and UDP checksums and verify it on packet receive.
// This part of test receive packets on 0 and 1 ports.
// Expects to get approximately 20% on 0 port and 80% on 1 port.
// Test also calculates sent/received ratios, number of broken packets and prints it when
// a predefined number of packets is received.
//
// Test with testScenario=2:
// This part of test receives packets on 0 port, split input flow according to rules
// in test-split.conf into 3 flows. 0 flow is dropped. 1,2 flows are sent back to
// 0 and 1 ports respectively.
//
// Test with testScenario=0:
// all these actions are made in one pipeline without actual send and receive.

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
	l3Rules *packet.L3Rules

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

	outport1 uint
	outport2 uint
	inport1  uint
	inport2  uint
	dpdkLogLevel *string

	fixMACAddrs  func(*packet.Packet, flow.UserContext)
	fixMACAddrs1 func(*packet.Packet, flow.UserContext)
	fixMACAddrs2 func(*packet.Packet, flow.UserContext)

	rulesString = "test-split.conf"
	filename    = &rulesString
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
	flag.DurationVar(&T, "timeout", T, "test start timeout. Packets sent during timeout do not affect test result")
	configFile := flag.String("config", "", "Specify json config file name (mandatory for VM)")
	target := flag.String("target", "", "Target host name from config file (mandatory for VM)")
	filename = flag.String("FILE", rulesString, "file with split rules in .conf format. If you change default port numbers, please, provide modified rules file too")
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
	if err := flow.SystemInit(&config); err != nil {
		return err
	}
	stabilityCommon.InitCommonState(configFile, target)
	fixMACAddrs = stabilityCommon.ModifyPacket[outport1].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs1 = stabilityCommon.ModifyPacket[outport1].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs2 = stabilityCommon.ModifyPacket[outport2].(func(*packet.Packet, flow.UserContext))

	if testScenario != 1 {
		var err error
		// Get splitting rules from access control file.
		l3Rules, err = packet.GetL3ACLFromORIG(*filename)
		if err != nil {
			return err
		}
	}
	if testScenario == 2 {
		inputFlow, err := flow.SetReceiver(uint8(inport1))
		if err != nil {
			return err
		}

		// Split packet flow based on ACL.
		flowsNumber := 3
		splittedFlows, err := flow.SetSplitter(inputFlow, l3Splitter, uint(flowsNumber), nil)
		if err != nil {
			return err
		}

		// "0" flow is used for dropping packets without sending them.
		if err := flow.SetStopper(splittedFlows[0]); err != nil {
			return err
		}

		if err := flow.SetHandler(splittedFlows[1], fixPackets1, nil); err != nil {
			return err
		}
		if err := flow.SetHandler(splittedFlows[2], fixPackets2, nil); err != nil {
			return err
		}

		// Send each flow to corresponding port. Send queues will be added automatically.
		if err := flow.SetSender(splittedFlows[1], uint8(outport1)); err != nil {
			return err
		}
		if err := flow.SetSender(splittedFlows[2], uint8(outport2)); err != nil {
			return err
		}

		// Begin to process packets.
		if err := flow.SystemStart(); err != nil {
			return err
		}
	} else {
		var m sync.Mutex
		testDoneEvent = sync.NewCond(&m)

		// Create first packet flow
		generatedFlow, err := flow.SetFastGenerator(generatePacket, speed, nil)
		if err != nil {
			return err
		}
		var flow1, flow2 *flow.Flow
		if testScenario == 1 {
			if err := flow.SetSender(generatedFlow, uint8(outport1)); err != nil {
				return err
			}
			// Create receiving flows and set a checking function for it
			flow1, err = flow.SetReceiver(uint8(inport1))
			if err != nil {
				return err
			}
			flow2, err = flow.SetReceiver(uint8(inport2))
			if err != nil {
				return err
			}
		} else {
			// Split packet flow based on ACL.
			flowsNumber := 3
			splittedFlows, err := flow.SetSplitter(generatedFlow, l3Splitter, uint(flowsNumber), nil)
			if err != nil {
				return err
			}
			// "0" flow is used for dropping packets without sending them.
			if err := flow.SetStopper(splittedFlows[0]); err != nil {
				return err
			}
			flow1 = splittedFlows[1]
			flow2 = splittedFlows[2]

			if err := flow.SetHandler(splittedFlows[1], fixPackets1, nil); err != nil {
				return err
			}
			if err := flow.SetHandler(splittedFlows[2], fixPackets2, nil); err != nil {
				return err
			}
		}
		if err := flow.SetHandler(flow1, checkInputFlow1, nil); err != nil {
			return err
		}
		if err := flow.SetHandler(flow2, checkInputFlow2, nil); err != nil {
			return err
		}

		if err := flow.SetStopper(flow1); err != nil {
			return err
		}
		if err := flow.SetStopper(flow2); err != nil {
			return err
		}

		// Start pipeline
		go func() {
			err = flow.SystemStart()
		}()
		if err != nil {
			return err
		}
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
	println()
	println("Group1 sent", sent1, "packets")
	println("Group1 received", recv1, "packets")
	println("Group1 ratio =", recv1*100/sent1, "%")
	println()
	println("Group2 sent", sent2, "packets")
	println("Group2 received", recv2, "packets")
	println("Group2 ratio =", recv2*100/sent2, "%")
	println()
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

func l3Splitter(currentPacket *packet.Packet, context flow.UserContext) uint {
	// Return number of flow to which put this packet. Based on ACL rules.
	return currentPacket.L3ACLPort(l3Rules)
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
