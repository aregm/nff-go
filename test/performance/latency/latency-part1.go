// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

// Latency test includes 2 parts:
//
// latency-part1:
// This part of test generates packets, puts time of generation into packet
// and send to port 0. Packets expected to be received back on 1 port. Received
// flow is partitioned in 100000:1 relation. For this 1 packet latency is
// calculated (current time minus time in packet) and then reported to channel.
// Test is finished when number of reported latency measurements = LAT_NUMBER
//
// latency-part2:
// This part of test receives packets on 0 port and send it back to 1 port.

// These are default test settings. Can be modified with command line.
var (
	LAT_NUMBER   int    = 500
	BINS         int    = 10
	SKIP_NUMBER  uint64 = 100000
	SPEED        uint64 = 1000000
	PASSED_LIMIT uint64 = 80

	PACKET_SIZE    uint64 = 128
	SERV_DATA_SIZE uint64 = 46 // Ether + IPv4 + UDP + 4

	DSTPORT_1 uint16 = 111
	DSTPORT_2 uint16 = 222

	outport uint
	inport uint
)

var (
	// PACKET_SIZE - SERV_DATA_SIZE
	payloadSize uint64 = 0

	// Counters of sent packets
	sentPackets uint64 = 0

	// Received flow is partitioned in two flows. Each flow has separate packet counter:
	// Counter of received packets, for which latency calculated
	checkedPackets uint64 = 0
	// Counter of other packets
	packetCounter uint64 = 0

	// Event is to notify when LAT_NUMBER number of packets are received
	testDoneEvent *sync.Cond = nil

	// Channel is used to report packet latencies
	latencies chan time.Duration
	// Channel to stop collecting latencies and print statistics
	stop chan string
	// Latency values are stored here for next processing
	latenciesStorage []time.Duration

	count uint64 = 0
)

func main() {
	flag.IntVar(&LAT_NUMBER, "LAT_NUMBER", LAT_NUMBER, "number of packets, for which latency should be reported")
	flag.IntVar(&BINS, "BINS", BINS, "number of bins")
	flag.Uint64Var(&SKIP_NUMBER, "SKIP_NUMBER", SKIP_NUMBER, "test calculates latency only for 1 of SKIP_NUMBER packets")
	flag.Uint64Var(&SPEED, "SPEED", SPEED, "speed of generator")
	flag.Uint64Var(&PASSED_LIMIT, "PASSED_LIMIT", PASSED_LIMIT, "received/sent minimum ratio to pass test")
	flag.Uint64Var(&PACKET_SIZE, "PACKET_SIZE", PACKET_SIZE, "size of packet")

	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport, "inport", 1, "port for receiver")

	latencies = make(chan time.Duration)
	stop = make(chan string)
	latenciesStorage = make([]time.Duration, 2*LAT_NUMBER)

	go latenciesLogger(latencies, stop)

	// Event needed to stop sending packets
	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	// Initialize YANFF library at 16 available cores
	flow.SystemInit(30)
	payloadSize = PACKET_SIZE - SERV_DATA_SIZE

	// Create packet flow
	outputFlow := flow.SetGenerator(generatePackets, SPEED, nil)
	outputFlow2 := flow.SetPartitioner(outputFlow, 350, 350)
	flow.SetSender(outputFlow, uint8(outport))
	flow.SetSender(outputFlow2, uint8(outport))

	// Create receiving flow and set a checking function for it
	inputFlow1 := flow.SetReceiver(uint8(inport))
	inputFlow2 := flow.SetReceiver(uint8(inport))
	inputFlow := flow.SetMerger(inputFlow1, inputFlow2)

	// Calculate latency only for 1 of SKIP_NUMBER packets.
	latFlow := flow.SetPartitioner(inputFlow, SKIP_NUMBER, 1)

	flow.SetHandler(latFlow, checkPackets, nil)
	flow.SetHandler(inputFlow, countPackets, nil)

	flow.SetStopper(inputFlow)
	flow.SetStopper(latFlow)

	// Start pipeline
	go flow.SystemStart()

	// Wait until enough latencies calculated
	testDoneEvent.L.Lock()
	testDoneEvent.Wait()
	testDoneEvent.L.Unlock()

	// Compose statistics
	sent := atomic.LoadUint64(&sentPackets)
	checked := atomic.LoadUint64(&checkedPackets)
	ignored := atomic.LoadUint64(&packetCounter)
	received := checked + ignored

	ratio := received * 100 / sent

	// Print report
	fmt.Println("Packet size", PACKET_SIZE, "bytes")
	fmt.Println("Requested speed", SPEED)
	fmt.Println("Sent", sent, "packets")
	fmt.Println("Received (total)", received, "packets")
	fmt.Println("Received/sent ratio =", ratio, "%")
	fmt.Println("Checked", checked, "packets")

	aver, stddev := statLatency(latenciesStorage)
	fmt.Println("Average = ", aver)
	fmt.Println("Stddev = ", stddev)
	displayHist(latenciesStorage, BINS)

	if ratio > PASSED_LIMIT {
		fmt.Println("TEST PASSED")
	} else {
		fmt.Println("TEST FAILED")
	}
}

func generatePackets(pkt *packet.Packet, context flow.UserContext) {
	atomic.AddUint64(&count, 1)
	packet.InitEmptyEtherIPv4UDPPacket(pkt, uint(payloadSize))
	if pkt == nil {
		panic("Failed to create new packet")
	}
	// We need different packets to gain from RSS
	if count%2 == 0 {
		pkt.UDP.DstPort = packet.SwapBytesUint16(DSTPORT_1)
	} else {
		pkt.UDP.DstPort = packet.SwapBytesUint16(DSTPORT_2)
	}

	ptr := (*PacketData)(pkt.Data)
	ptr.SendTime = time.Now()
	atomic.AddUint64(&sentPackets, 1)
}

// This function take latencies from channel, and put values to array.
func latenciesLogger(ch <-chan time.Duration, stop <-chan string) {
	sum := time.Duration(0)
	count := 0
	for {
		select {
		case lat := <-ch:
			sum += lat
			latenciesStorage[count] = lat
			count += 1
		case _ = <-stop:
			testDoneEvent.Signal()
			break
		}
	}
}

// Count and check packets in received flow
func checkPackets(pkt *packet.Packet, context flow.UserContext) {
	checkCount := atomic.AddUint64(&checkedPackets, 1)

	offset := pkt.ParseL4Data()
	if offset < 0 {
		fmt.Printf("ParseL4Data returned negative value:\noffset:%d,\n packet: %x\n", offset, pkt.GetRawPacketBytes())
	} else {
		ptr := (*PacketData)(pkt.Data)
		RecvTime := time.Now()
		lat := RecvTime.Sub(ptr.SendTime)
		// Report latency
		latencies <- lat
	}

	if checkCount >= uint64(LAT_NUMBER) {
		stop <- "stop"
	}
}

func countPackets(pkt *packet.Packet, context flow.UserContext) {
	atomic.AddUint64(&packetCounter, 1)
}

type PacketData struct {
	SendTime time.Time
}

// Display summary on calculated latencies
func displayHist(times []time.Duration, maxBins int) {
	min := time.Duration(1 << 10 * time.Second)
	max := time.Duration(0)
	for _, t := range times[0:LAT_NUMBER] {
		if t < min {
			min = t
		}
		if t > max {
			max = t
		}
	}

	fmt.Println("min latency=", min)
	fmt.Println("max latency=", max)

	step := (max - min) / time.Duration(maxBins)

	bounds := make([]time.Duration, maxBins+1)
	bounds[0] = min - 1
	for i := 1; i < maxBins+1; i++ {
		bounds[i] = bounds[i-1] + step
	}
	bounds[maxBins] = max

	// Count observations in each interval
	histObs := make([]int, maxBins)
	for i := 0; i < LAT_NUMBER; i++ {
		t := times[i]
		for j := 1; j < maxBins+1; j++ {
			if t > bounds[j-1] && t <= bounds[j] {
				histObs[j-1]++
			}
		}
	}
	// Displaying latency intervals and counts
	for i := 0; i < maxBins; i++ {
		fmt.Printf("Interval %d: (%v, %v] count = %d - %v\n", i, bounds[i], bounds[i+1], histObs[i],
			float32(histObs[i])/float32(LAT_NUMBER))
	}
}

// Calculate geomean for first LAT_NUMBER observations
func geomeanLatency(times []time.Duration) time.Duration {
	g := math.Pow(float64(times[0]), 1/float64(LAT_NUMBER))
	for i := 1; i < LAT_NUMBER; i++ {
		g = g * math.Pow(float64(times[i]), 1/float64(LAT_NUMBER))
	}
	return time.Duration(g)
}

// Calculate average and stddev for first LAT_NUMBER observations
func statLatency(times []time.Duration) (time.Duration, time.Duration) {
	var g time.Duration
	var s float64
	for i := 0; i < LAT_NUMBER; i++ {
		g += times[i]
	}
	aver := float64(int(g) / LAT_NUMBER)

	for i := 0; i < LAT_NUMBER; i++ {
		s += math.Pow(float64(times[i])-aver, 2)
	}
	return time.Duration(aver), time.Duration(math.Sqrt(s / float64(LAT_NUMBER)))
}
