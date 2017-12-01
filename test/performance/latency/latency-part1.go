// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
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
// Test is finished when number of reported latency measurements = latNumber
//
// latency-part2:
// This part of test receives packets on 0 port and send it back to 1 port.

// These are default test settings. Can be modified with command line.
var (
	latNumber          = 500
	bins               = 10
	skipNumber  uint64 = 100000
	speed       uint64 = 1000000
	passedLimit uint64 = 80

	packetSize   uint64 = 128
	servDataSize uint64 = 46 // Ether + IPv4 + UDP + 4

	dstPort1 uint16 = 111
	dstPort2 uint16 = 222

	outport uint
	inport  uint
)

var (
	// packetSize - servDataSize
	payloadSize uint64

	// Counters of sent packets
	sentPackets uint64

	// Received flow is partitioned in two flows. Each flow has separate packet counter:
	// Counter of received packets, for which latency calculated
	checkedPackets uint64
	// Counter of other packets
	packetCounter uint64

	// Event is to notify when latNumber number of packets are received
	testDoneEvent *sync.Cond

	// Channel is used to report packet latencies
	latencies chan time.Duration
	// Channel to stop collecting latencies and print statistics
	stop chan string
	// Latency values are stored here for next processing
	latenciesStorage []time.Duration

	count uint64
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	flag.IntVar(&latNumber, "latNumber", latNumber, "number of packets, for which latency should be reported")
	flag.IntVar(&bins, "bins", bins, "number of bins")
	flag.Uint64Var(&skipNumber, "skipNumber", skipNumber, "test calculates latency only for 1 of skipNumber packets")
	flag.Uint64Var(&speed, "speed", speed, "speed of generator")
	flag.Uint64Var(&passedLimit, "passedLimit", passedLimit, "received/sent minimum ratio to pass test")
	flag.Uint64Var(&packetSize, "packetSize", packetSize, "size of packet")

	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport, "inport", 1, "port for receiver")

	latencies = make(chan time.Duration)
	stop = make(chan string)
	latenciesStorage = make([]time.Duration, 2*latNumber)

	go latenciesLogger(latencies, stop)

	// Event needed to stop sending packets
	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	// Initialize YANFF library at 30 available cores
	config := flow.Config{
		CPUList: "0-29",
	}
	CheckFatal(flow.SystemInit(&config))
	payloadSize = packetSize - servDataSize

	// Create packet flow
	outputFlow, err := flow.SetGenerator(generatePackets, speed, nil)
	CheckFatal(err)
	outputFlow2, err := flow.SetPartitioner(outputFlow, 350, 350)
	CheckFatal(err)

	CheckFatal(flow.SetSender(outputFlow, uint8(outport)))
	CheckFatal(flow.SetSender(outputFlow2, uint8(outport)))

	// Create receiving flow and set a checking function for it
	inputFlow1, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)
	inputFlow2, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)
	inputFlow, err := flow.SetMerger(inputFlow1, inputFlow2)
	CheckFatal(err)

	// Calculate latency only for 1 of skipNumber packets.
	latFlow, err := flow.SetPartitioner(inputFlow, skipNumber, 1)
	CheckFatal(err)

	CheckFatal(flow.SetHandler(latFlow, checkPackets, nil))
	CheckFatal(flow.SetHandler(inputFlow, countPackets, nil))

	CheckFatal(flow.SetStopper(inputFlow))
	CheckFatal(flow.SetStopper(latFlow))

	// Start pipeline
	go func() {
		CheckFatal(flow.SystemStart())
	}()

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
	fmt.Println("Packet size", packetSize, "bytes")
	fmt.Println("Requested speed", speed)
	fmt.Println("Sent", sent, "packets")
	fmt.Println("Received (total)", received, "packets")
	fmt.Println("Received/sent ratio =", ratio, "%")
	fmt.Println("Checked", checked, "packets")

	aver, stddev := statLatency(latenciesStorage)
	fmt.Println("Average = ", aver)
	fmt.Println("Stddev = ", stddev)
	displayHist(latenciesStorage, bins)

	if ratio > passedLimit {
		fmt.Println("TEST PASSED")
	} else {
		fmt.Println("TEST FAILED")
	}
}

func generatePackets(pkt *packet.Packet, context flow.UserContext) {
	atomic.AddUint64(&count, 1)
	if pkt == nil {
		fmt.Println("TEST FAILED")
		log.Fatal("Failed to create new packet")
	}
	if packet.InitEmptyIPv4UDPPacket(pkt, uint(payloadSize)) == false {
		fmt.Println("TEST FAILED")
		log.Fatal("Failed to init empty packet")
	}

	// We need different packets to gain from RSS
	if count%2 == 0 {
		pkt.GetUDPForIPv4().DstPort = packet.SwapBytesUint16(dstPort1)
	} else {
		pkt.GetUDPForIPv4().DstPort = packet.SwapBytesUint16(dstPort2)
	}

	ptr := (*packetData)(pkt.Data)
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
			count++
		case _ = <-stop:
			testDoneEvent.Signal()
			break
		}
	}
}

// Count and check packets in received flow
func checkPackets(pkt *packet.Packet, context flow.UserContext) {
	checkCount := atomic.AddUint64(&checkedPackets, 1)

	offset := pkt.ParseData()
	if offset < 0 {
		fmt.Printf("ParseData returned negative value:\noffset:%d,\n packet: %x\n", offset, pkt.GetRawPacketBytes())
	} else {
		ptr := (*packetData)(pkt.Data)
		RecvTime := time.Now()
		lat := RecvTime.Sub(ptr.SendTime)
		// Report latency
		latencies <- lat
	}

	if checkCount >= uint64(latNumber) {
		stop <- "stop"
	}
}

func countPackets(pkt *packet.Packet, context flow.UserContext) {
	atomic.AddUint64(&packetCounter, 1)
}

type packetData struct {
	SendTime time.Time
}

// Display summary on calculated latencies
func displayHist(times []time.Duration, maxBins int) {
	min := time.Duration(1 << 10 * time.Second)
	max := time.Duration(0)
	for _, t := range times[0:latNumber] {
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
	for i := 0; i < latNumber; i++ {
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
			float32(histObs[i])/float32(latNumber))
	}
}

// Calculate geomean for first latNumber observations
func geomeanLatency(times []time.Duration) time.Duration {
	g := math.Pow(float64(times[0]), 1/float64(latNumber))
	for i := 1; i < latNumber; i++ {
		g = g * math.Pow(float64(times[i]), 1/float64(latNumber))
	}
	return time.Duration(g)
}

// Calculate average and stddev for first latNumber observations
func statLatency(times []time.Duration) (time.Duration, time.Duration) {
	var g time.Duration
	var s float64
	for i := 0; i < latNumber; i++ {
		g += times[i]
	}
	aver := float64(int(g) / latNumber)

	for i := 0; i < latNumber; i++ {
		s += math.Pow(float64(times[i])-aver, 2)
	}
	return time.Duration(aver), time.Duration(math.Sqrt(s / float64(latNumber)))
}
