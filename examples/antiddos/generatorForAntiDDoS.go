// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This part generates packets for anti DDoS example.
// Packets are generated of random size [64, 1024]
// half TCP, half UDP 80% of flood and 20% of good
// packets which src addresses are in goodAddresses list.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

const (
	goodDataListSize = 4
	// Rates to estimate the work of filter
	floodRateDropMin    = 0.5
	nonFloodRateDropMax = 0.1
)

var (
	speed        uint64 = 6000000 // 6000000 for 544 (average for range [64, 1024)]) bytes pkt ~ 26Gb/s
	totalPackets uint64
	payloadSize  uint
	recvPackets  uint64
	sentPackets  uint64
	sentNonFlood uint64
	gotNonFlood  uint64

	// needed to finish work and print statistics after
	// we received totalPackets number of pkts
	exampleDoneEvent *sync.Cond

	outPort int
	inPort  int
	// addresses imitating users sending non flood
	// flooding user's addresses will be generated
	goodAddresses = [goodDataListSize]uint32{packet.SwapBytesUint32(1235),
		packet.SwapBytesUint32(980),
		packet.SwapBytesUint32(2405),
		packet.SwapBytesUint32(3540)}
	// ports corresponding to addresses of users sending non flood
	goodPorts = [goodDataListSize]uint16{packet.SwapBytesUint16(1),
		packet.SwapBytesUint16(2),
		packet.SwapBytesUint16(3),
		packet.SwapBytesUint16(4)}
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	flag.Uint64Var(&speed, "speed", speed, "speed of generator, Pkts/s")
	flag.IntVar(&outPort, "outPort", 0, "port to send")
	flag.IntVar(&inPort, "inPort", 0, "port to receive")
	flag.Uint64Var(&totalPackets, "totalPackets", 100000000, "finish work when total number of packets received")
	flag.Parse()
	// Init YANFF system at requested number of cores.
	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))

	exampleDoneEvent = sync.NewCond(&sync.Mutex{})

	// Create first packet flow
	outputFlow, err := flow.SetFastGenerator(generatePacket, speed, nil)
	CheckFatal(err)
	CheckFatal(flow.SetSender(outputFlow, uint8(outPort)))
	inputFlow, err := flow.SetReceiver(uint8(inPort))
	CheckFatal(err)
	CheckFatal(flow.SetHandler(inputFlow, checkInputFlow, nil))
	CheckFatal(flow.SetStopper(inputFlow))
	go randomizeSize()
	// Start pipeline
	go func() {
		CheckFatal(flow.SystemStart())
	}()

	// Wait for enough packets to arrive
	exampleDoneEvent.L.Lock()
	exampleDoneEvent.Wait()
	exampleDoneEvent.L.Unlock()

	sent := atomic.LoadUint64(&sentPackets)
	received := atomic.LoadUint64(&recvPackets)

	nonFloods := atomic.LoadUint64(&sentNonFlood)
	floods := sent - nonFloods
	nonFloodr := atomic.LoadUint64(&gotNonFlood)
	floodr := received - nonFloodr

	fmt.Println("Sent", sent, "packets")
	fmt.Println("Received", received, "packets")
	fmt.Println("Flood Received", floodr, "packets")
	fmt.Println("Not flood Received", nonFloodr, "packets")
	fmt.Println("Flood sent", floods, "packets")
	fmt.Println("Not flood sent", nonFloods, "packets")

	floodDropRate := float64((floods - floodr)) / float64(floods)
	nonFloodDropRate := float64((nonFloods - nonFloodr)) / float64(nonFloods)
	if floodDropRate < floodRateDropMin || nonFloodDropRate > nonFloodRateDropMax {
		fmt.Println("TEST FAILED")
	} else {
		fmt.Println("TEST PASSED")
	}
	fmt.Println("Percent dropped bad: ", 100*floodDropRate, "Percent dropped good: ", 100*nonFloodDropRate)
	fmt.Println("Percent dropped at all: ", 100*float64(sent-received)/float64(sent))
}

// Function to use in generator
func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	var address *uint32
	var port *uint16

	if pkt == nil {
		panic("Failed to create new packet")
	}

	if sentPackets%2 == 0 {
		if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
			panic("Failed to init empty udp packet")
		}
		port = &(pkt.GetUDPForIPv4().SrcPort)
	} else {
		if packet.InitEmptyIPv4TCPPacket(pkt, payloadSize) == false {
			panic("Failed to init empty tcp packet")
		}
		port = &(pkt.GetTCPForIPv4().SrcPort)
	}
	address = &(pkt.GetIPv4().SrcAddr)

	if sentPackets%5 == 0 {
		indx := rand.Intn(goodDataListSize)
		*address = goodAddresses[indx]
		*port = goodPorts[indx]
		atomic.AddUint64(&sentNonFlood, 1)
	} else {
		*address = packet.SwapBytesUint32(uint32(sentPackets))
		*port = packet.SwapBytesUint16(uint16(sentPackets))
	}

	atomic.AddUint64(&sentPackets, 1)
}

func checkInputFlow(pkt *packet.Packet, context flow.UserContext) {
	var srcPort uint16
	recvCount := atomic.AddUint64(&recvPackets, 1)

	pktIPv4, _, _ := pkt.ParseAllKnownL3()
	if pktIPv4 != nil {
		pktTCP, pktUDP, _ := pkt.ParseAllKnownL4ForIPv4()

		if pktTCP != nil {
			srcPort = pktTCP.SrcPort
		} else if pktUDP != nil {
			srcPort = pktUDP.SrcPort
		}
		if isSrcGood(pktIPv4.SrcAddr, srcPort) {
			atomic.AddUint64(&gotNonFlood, 1)
		}
	}
	if recvCount >= totalPackets {
		exampleDoneEvent.Signal()
	}
}

func isSrcGood(srcAddr uint32, srcPort uint16) bool {
	for i := 0; i < goodDataListSize; i++ {
		if srcAddr == goodAddresses[i] && srcPort == goodPorts[i] {
			return true
		}
	}
	return false
}

func randomizeSize() {
	for {
		// once in a time calculate new size
		payloadSize = uint(rand.Intn(1024-64) + 64)
		time.Sleep(100 * time.Millisecond)
	}
}
