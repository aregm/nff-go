// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

// This is 1 part of latency test
// For 2 part can be any of perf_light, perf_main, perf_seq
// This part of test generates packets, puts time of generation into packet
// and send.
// Received flow is partitioned in skipNumber:1 relation. For this 1 packet latency is
// calculated (current time minus time in packet) and then reported to channel.
// Test is finished when number of reported latency measurements == latNumber

// These are default test settings. Can be modified with command line.
var (
	latNumber          = 500
	skipNumber  uint64 = 10000
	speed       uint64 = 1000000
	passedLimit uint64 = 80

	packetSize   uint64 = 128
	servDataSize uint64 = types.EtherLen + types.IPv4MinLen + types.UDPLen + crcLen

	outport uint16
	inport  uint16

	noscheduler  bool
	dpdkLogLevel string
)

const (
	crcLen          = 4
	dstPort1 uint16 = 111
	dstPort2 uint16 = 222
)

var (
	// packetSize - servDataSize
	payloadSize uint64
	// Counters of sent packets
	sentPackets uint64

	// Received flow is partitioned in two flows. Each flow has separate packet counter:
	// Counter of received packets, for which latency calculated
	checkedPktsCount uint64
	// Counter of other packets
	uncheckedPktsCount uint64

	// Event is to notify when latNumber number of packets are received
	testDoneEvent *sync.Cond
	// Channel is used to report packet latencies
	latencies chan time.Duration
	// Channel to stop collecting latencies and print statistics
	stop chan string
	// Latency values are stored here for next processing
	latenciesStorage []time.Duration
	// Time when piplene started
	progStart time.Time
	// T second timeout is used to let generator reach required speed
	// During timeout packets are skipped and not counted
	T = 10 * time.Second
)

func main() {
	flag.IntVar(&latNumber, "latNumber", latNumber, "number of packets, for which latency should be reported")
	flag.Uint64Var(&skipNumber, "skipNumber", skipNumber, "test calculates latency only for 1 of skipNumber packets")
	flag.Uint64Var(&speed, "speed", speed, "speed of generator")
	flag.Uint64Var(&passedLimit, "passedLimit", passedLimit, "received/sent minimum ratio to pass test")
	flag.Uint64Var(&packetSize, "packetSize", packetSize, "size of packet")
	outport := flag.Uint("outport", 0, "port for sender")
	inport := flag.Uint("inport", 1, "port for receiver")
	flag.BoolVar(&noscheduler, "no-scheduler", false, "disable scheduler")
	flag.DurationVar(&T, "timeout", T, "test start delay, needed to stabilize speed. Packets sent during timeout do not affect test result")
	flag.StringVar(&dpdkLogLevel, "dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()

	latencies = make(chan time.Duration)
	stop = make(chan string)
	latenciesStorage = make([]time.Duration, latNumber)

	go latenciesLogger(latencies, stop)

	// Event needed to stop sending packets
	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	// Initialize NFF-GO library
	if err := initDPDK(); err != nil {
		fmt.Printf("fail: %v\n", err)
	}
	payloadSize = packetSize - servDataSize

	// Create packet flow
	outputFlow, _, err := flow.SetFastGenerator(generatePackets, speed, nil)
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetSender(outputFlow, uint16(*outport)))

	// Create receiving flow and set a checking function for it
	inputFlow, err := flow.SetReceiver(uint16(*inport))
	flow.CheckFatal(err)

	// Calculate latency only for 1 of skipNumber packets
	latFlow, err := flow.SetPartitioner(inputFlow, skipNumber, 1)
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetHandler(latFlow, checkPackets, nil))
	flow.CheckFatal(flow.SetHandler(inputFlow, countPackets, nil))

	flow.CheckFatal(flow.SetStopper(inputFlow))
	flow.CheckFatal(flow.SetStopper(latFlow))

	progStart = time.Now()
	// Start pipeline
	go func() {
		flow.CheckFatal(flow.SystemStart())
	}()

	// Wait until enough latencies calculated
	testDoneEvent.L.Lock()
	testDoneEvent.Wait()
	testDoneEvent.L.Unlock()

	// Compose statistics
	composeStatistics()
}

func initDPDK() error {
	// Init NFF-GO system
	config := flow.Config{
		DisableScheduler: noscheduler,
		DPDKArgs:         []string{dpdkLogLevel},
	}
	return flow.SystemInit(&config)
}

func composeStatistics() {
	sent := atomic.LoadUint64(&sentPackets)
	checked := atomic.LoadUint64(&checkedPktsCount)
	ignored := atomic.LoadUint64(&uncheckedPktsCount)
	received := checked + ignored

	ratio := received * 100 / sent

	fmt.Println("pkt_size=", packetSize, "bytes")
	fmt.Println("speed=", speed)
	fmt.Println("sent=", sent, "packets")
	fmt.Println("received_total=", received, "packets")
	fmt.Println("received/sent=", ratio, "%")
	fmt.Println("checked=", checked, "packets")
	fmt.Println("ignored=", ignored, "packets")

	stat := calcStats(latenciesStorage)
	fmt.Println("median=", stat.median, "μs")
	fmt.Println("average=", stat.average, "μs")
	fmt.Println("stddev=", stat.stddev, "μs")

	if ratio > passedLimit {
		fmt.Println("TEST PASSED")
	} else {
		fmt.Println("TEST FAILED")
	}
}

func generatePackets(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		println("TEST FAILED")
		log.Fatal("Failed to create new packet")
	}
	if packet.InitEmptyIPv4UDPPacket(pkt, uint(payloadSize)) == false {
		println("TEST FAILED")
		log.Fatal("Failed to init empty packet")
	}
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()

	// We need different packets to gain from RSS
	if atomic.LoadUint64(&sentPackets)%2 == 0 {
		udp.DstPort = packet.SwapBytesUint16(dstPort1)
	} else {
		udp.DstPort = packet.SwapBytesUint16(dstPort2)
	}

	if time.Since(progStart) >= T {
		ptr := (*packetData)(pkt.Data)
		ptr.SendTime = time.Now()
		atomic.AddUint64(&sentPackets, 1)
	}

	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))
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

// Check packets in received flow, calculate latencies and put to channel
func checkPackets(pkt *packet.Packet, context flow.UserContext) {
	checkCount := atomic.LoadUint64(&checkedPktsCount)
	if pkt.ParseData() < 0 {
		println("Cannot parse Data, skip")
	} else if checkCount >= uint64(latNumber) {
		stop <- "stop"
	} else {
		sendTime := (*packetData)(pkt.Data).SendTime
		if !sendTime.IsZero() {
			atomic.AddUint64(&checkedPktsCount, 1)
			lat := time.Now().Sub(sendTime)
			latencies <- lat
		}
	}
}

func countPackets(pkt *packet.Packet, context flow.UserContext) {
	if pkt.ParseData() < 0 {
		println("Cannot parse Data, skip")
	} else {
		sendTime := (*packetData)(pkt.Data).SendTime
		if !sendTime.IsZero() {
			atomic.AddUint64(&uncheckedPktsCount, 1)
		}
	}
}

type packetData struct {
	SendTime time.Time
}

type latencyStat struct {
	median  float64
	average float64
	stddev  float64
}

// Calculate median, average and stddev time (in μs)
func calcStats(times []time.Duration) (stat latencyStat) {
	stat.median = median(times)

	g := time.Duration(0)
	for i := 0; i < latNumber; i++ {
		g += times[i]
	}
	stat.average = toMicroseconds(time.Duration(int64(g) / int64(latNumber)))

	s := float64(0)
	for i := 0; i < latNumber; i++ {
		s += math.Pow(float64(times[i])-float64(stat.average), 2)
	}
	stat.stddev = toMicroseconds(time.Duration(math.Sqrt(s / float64(latNumber))))
	return
}

func median(arr []time.Duration) float64 {
	len := len(arr)
	tmp := make([]time.Duration, len)
	copy(tmp, arr)
	sort.Slice(tmp, func(i, j int) bool { return tmp[i] < tmp[j] })
	if len%2 == 0 {
		return toMicroseconds(tmp[len/2]/2 + tmp[len/2+1]/2)
	} else {
		return toMicroseconds(tmp[len/2+1])
	}
}

func toMicroseconds(t time.Duration) float64 {
	return t.Seconds() * 1e6
}
