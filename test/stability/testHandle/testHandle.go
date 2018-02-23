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
)

// Test with testScenario=1:
// sends packets to 0 port, receives from 0 and 1 ports.
// This part of test generates three packet flows (1st, 2nd and 3rd), merges them into one flow
// and send it to 0 port. Packets in original 1st, 2nd and 3rd flows has UDP destination addresses
// dstPort1, dstPort2, dstPort3 respectively. For each packet sender calculates
// IPv4 and UDP checksums and verify it on packet receive.
// This part of test receive packets on 0 port, expects to receive ~33% of packets.
// Test also calculates number of broken packets and prints it when a predefined number
// of packets is received.
//
// Test with testScenario=2:
// This part of test receives packets on 0 port, separate input flow according to rules
// in test-separate-l3rules.conf into 2 flows. Accepted flow sent to 0 port, rejected flow is stopped.
//
// Test with testScenario=0:
// all these actions are made in one pipeline without actual send and receive.

const (
	// Test expects to receive 33% of packets on 0 port.
	// Test is PASSSED, if p1 is in [low1;high1]
	eps   = 5
	high1 = 33 + eps
	low1  = 33 - eps
)

var (
	totalPackets uint64 = 10000000
	l3Rules      *packet.L3Rules
	// Payload is 16 byte md5 hash sum of headers
	payloadSize uint   = 16
	speed       uint64 = 1000000

	sentPacketsGroup1 uint64
	sentPacketsGroup2 uint64
	sentPacketsGroup3 uint64

	sent          uint64
	recv          uint64
	brokenPackets uint64

	dstPort1 uint16 = 111
	dstPort2 uint16 = 222
	dstPort3 uint16 = 333

	testDoneEvent *sync.Cond
	progStart     time.Time

	// T second timeout is used to let generator reach required speed
	// During timeout packets are skipped and not counted
	T = 10 * time.Second

	outport uint
	inport  uint
	dpdkLogLevel *string

	rulesConfig = "test-handle-l3rules.conf"
)

func main() {
	var testScenario uint
	flag.UintVar(&testScenario, "testScenario", 0, "1 to use 1st part scenario, 2 snd, 0 to use one-machine test")
	flag.Uint64Var(&speed, "speed", speed, "speed of 1 and 2 generators, Pkts/s")
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.Uint64Var(&totalPackets, "number", totalPackets, "total number of packets to receive by test")
	flag.DurationVar(&T, "timeout", T, "test start delay, needed to stabilize speed. Packets sent during timeout do not affect test result")
	dpdkLogLevel = flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()

	if err := executeTest(testScenario); err != nil {
		fmt.Printf("fail: %+v\n", err)
	}
}

func executeTest(testScenario uint) error {
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
	if testScenario != 1 {
		var err error
		// Get splitting rules from access control file.
		l3Rules, err = packet.GetL3ACLFromORIG(rulesConfig)
		if err != nil {
			return err
		}
	}
	if testScenario == 2 {
		// Receive packets from 0 port
		flow1, err := flow.SetReceiver(uint8(inport))
		if err != nil {
			return err
		}

		// Handle packet flow
		// ~33% of packets should left in flow1
		if err := flow.SetHandlerDrop(flow1, l3Handler, nil); err != nil {
			return err
		}

		// Send each flow to corresponding port. Send queues will be added automatically.
		if err := flow.SetSender(flow1, uint8(outport)); err != nil {
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
		outFlow, err := flow.SetFastGenerator(generatePacket, speed, nil)
		if err != nil {
			return err
		}

		var finalFlow *flow.Flow
		if testScenario == 1 {
			var err error
			if err := flow.SetSender(outFlow, uint8(outport)); err != nil {
				return err
			}
			// Create receiving flows and set a checking function for it
			finalFlow, err = flow.SetReceiver(uint8(inport))
			if err != nil {
				return err
			}
		} else {
			finalFlow = outFlow
			if err := flow.SetHandlerDrop(finalFlow, l3Handler, nil); err != nil {
				return err
			}
		}
		if err := flow.SetHandler(finalFlow, checkInputFlow, nil); err != nil {
			return err
		}
		if err := flow.SetStopper(finalFlow); err != nil {
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

func l3Handler(pkt *packet.Packet, context flow.UserContext) bool {
	return pkt.L3ACLPermit(l3Rules)
}

func composeStatistics() {
	// Compose statistics
	sent1 := sentPacketsGroup1
	sent2 := sentPacketsGroup2
	sent3 := sentPacketsGroup3
	sentTotal := sent1 + sent2 + sent3

	received := atomic.LoadUint64(&recv)

	var p int
	if sentTotal != 0 {
		p = int(received * 100 / sentTotal)
	}
	broken := atomic.LoadUint64(&brokenPackets)

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")
	println("Proportion of received packets ", p, "%")
	println("Broken = ", broken, "packets")

	// Test is PASSSED, if p is ~33%
	if p <= high1 && p >= low1 {
		println("TEST PASSED")
	} else {
		println("TEST FAILED")
	}
}

func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		log.Fatal("Failed to create new packet")
	}
	if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
		log.Fatal("Failed to init empty packet")
	}
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	t := sent % 3
	switch t {
	case 0:
		udp.DstPort = packet.SwapBytesUint16(dstPort1)
	case 1:
		udp.DstPort = packet.SwapBytesUint16(dstPort2)
	case 2:
		udp.DstPort = packet.SwapBytesUint16(dstPort3)
	}
	sent++

	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))

	// We do not consider the start time of the system in this test
	if time.Since(progStart) < T {
		return
	}

	switch t {
	case 0:
		atomic.AddUint64(&sentPacketsGroup1, 1)
	case 1:
		atomic.AddUint64(&sentPacketsGroup2, 1)
	case 2:
		atomic.AddUint64(&sentPacketsGroup3, 1)
	}
}

func checkInputFlow(pkt *packet.Packet, context flow.UserContext) {
	if time.Since(progStart) < T {
		return
	}

	offset := pkt.ParseData()
	if offset < 0 {
		println("ParseData returned negative value", offset)
		// Some received packets are not generated by this example
		// They cannot be parsed due to unknown protocols, skip them
	} else {
		ipv4 := pkt.GetIPv4()
		udp := pkt.GetUDPForIPv4()
		recvIPv4Cksum := packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
		recvUDPCksum := packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))

		if recvIPv4Cksum != ipv4.HdrChecksum || recvUDPCksum != udp.DgramCksum {
			// Packet is broken
			atomic.AddUint64(&brokenPackets, 1)
			return
		}
		atomic.AddUint64(&recv, 1)
	}
	if recv >= totalPackets {
		testDoneEvent.Signal()
	}
}
