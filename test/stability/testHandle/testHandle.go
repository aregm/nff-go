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

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
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
	totalPackets = 10000000

	// Test expects to receive 33% of packets on 0 port.
	// Test is PASSSED, if p1 is in [low1;high1]
	eps   = 5
	high1 = 33 + eps
	low1  = 33 - eps
)

var (
	l3Rules *packet.L3Rules
	// Payload is 16 byte md5 hash sum of headers
	payloadSize uint = 16
	d           uint = 10

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

	outport uint
	inport  uint

	rulesConfig = "test-handle-l3rules.conf"
)

func main() {
	var testScenario uint
	flag.UintVar(&testScenario, "testScenario", 0, "1 to use 1st part scenario, 2 snd, 0 to use one-machine test")
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport, "inport", 0, "port for receiver")
	flag.Parse()

	if err := executeTest(testScenario); err != nil {
		fmt.Printf("fail: %+v\n", err)
	}
}

func executeTest(testScenario uint) error {
	if testScenario > 3 || testScenario < 0 {
		return errors.New("testScenario should be in interval [0, 3]")
	}
	// Init YANFF system
	config := flow.Config{}
	if err := flow.SystemInit(&config); err != nil { return err }
	if testScenario != 1 {
		var err error
		// Get splitting rules from access control file.
		l3Rules, err = packet.GetL3ACLFromORIG(rulesConfig)
		if err != nil { return err }
	}
	if testScenario == 2 {
		// Receive packets from 0 port
		flow1, err := flow.SetReceiver(uint8(inport))
		if err != nil { return err }

		// Handle packet flow
		// ~33% of packets should left in flow1
		if err := flow.SetHandlerDrop(flow1, l3Handler, nil); err != nil { return err }

		// Send each flow to corresponding port. Send queues will be added automatically.
		if err := flow.SetSender(flow1, uint8(outport)); err != nil { return err }

		// Begin to process packets.
		if err := flow.SystemStart(); err != nil { return err }
	} else {
		var m sync.Mutex
		testDoneEvent = sync.NewCond(&m)

		// Create first packet flow
		outFlow := flow.SetGenerator(generatePacket, nil)
		var finalFlow *flow.Flow
		if testScenario == 1 {
			var err error
			if err := flow.SetSender(outFlow, uint8(outport)); err != nil { return err }
			// Create receiving flows and set a checking function for it
			finalFlow, err = flow.SetReceiver(uint8(outport))
			if err != nil { return err }
		} else {
			finalFlow = outFlow
			if err := flow.SetHandlerDrop(finalFlow, l3Handler, nil); err != nil { return err }
		}
		if err := flow.SetHandler(finalFlow, checkInputFlow, nil); err != nil { return err }
		if err := flow.SetStopper(finalFlow); err != nil { return err }

		var err error
		// Start pipeline
		go func() {
			err = flow.SystemStart()
		}()
		if err != nil { return err }

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
	sent := sent1 + sent2 + sent3

	received := atomic.LoadUint64(&recv)

	var p int
	if sent != 0 {
		p = int(received * 100 / sent)
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
	switch sent % 3 {
	case 0:
		udp.DstPort = packet.SwapBytesUint16(dstPort1)
		sentPacketsGroup1++
	case 1:
		udp.DstPort = packet.SwapBytesUint16(dstPort2)
		sentPacketsGroup2++
	case 2:
		udp.DstPort = packet.SwapBytesUint16(dstPort3)
		sentPacketsGroup3++
	}
	sent++

	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))

	if sentPacketsGroup1 > totalPackets/3 {
		time.Sleep(time.Second * time.Duration(d))
		println("TEST FAILED")
	}
}

func checkInputFlow(pkt *packet.Packet, context flow.UserContext) {
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
	// TODO 80% of requested number of packets.
	if recv >= totalPackets/32*8 {
		testDoneEvent.Signal()
	}
}
