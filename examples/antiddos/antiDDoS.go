// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Below is an example of simple anti DDoS function. Type of atack is L4 flood.
// DDoS attack is considered when only one packet is sent from each of multiple
// source addresses with high frequrncy.
// Packets are split on flows (NOT YANFF flows) – abstraction of all packets
// came from one scr addr and src port.
// Layer 4 anti DDoS filter will be based on 2 indicators:
// * Rate of inter-arrival times within [0, 200 us) (IAT):
// Number of packets came in [0, 200 us)  / number of packets came in
// * Rate of flows having only one packet (PPF):
// Number of flows having 1 packet / number of flows
// If IAT > IATthreshold , PPF > PPFthreshold we consider DDOS is going.
// If DDOS is going we drop incoming packets that were not seen earlier, but record them for future.

package main

import (
	"flag"
	"fmt"
	"hash/fnv"
	"os"
	"sync/atomic"
	"time"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

// Constants are taken from paper:
// Huong T. T., Thanh N. H. "Software defined networking-based one-packet DDoS mitigation architecture"//
// Proceedings of the 11th International Conference on Ubiquitous Information Management and Communication. – ACM, 2017. – С. 110.
const (
	monitoringWindow = 6  // 6s - expiration time of flow in a table
	size2InPow       = 28 // 2**size2InPow will be size of a table
	// size is made a pow of 2 to make & instead of %, it is faster
	size                    = uint32(1 << size2InPow)  // table size
	iatThreshold            = float64(0.9)             // when iat > iatThreshold, we consider DDoS is going
	ppfThreshold            = float64(0.8)             // when ppf > ppfThreshold, we consider DDoS is going
	bitsForTime             = 14                       //time takes 14 last bits of flow record
	timeStampMask           = ((1 << bitsForTime) - 1) // 14 last bits mask for timestamp
	getNumOfPacketsMask     = (3 << bitsForTime)       // 2 1st bits mask for num of packets
	timeShiftToGetSeconds   = 30                       // pow(2, 30) is approximately 1e9
	iatValueNanos           = 200000                   // 200 us converted to nanoseconds
	ddosCalculationInterval = 5 * time.Millisecond     // interval to recount ddos metrics
	// if it is large, reaction on ddos will be slow, if it is small, it will
	// slow down the work of handlers due to concurrent access
)

var (
	inPort  int
	outPort int
	// flowTable stores number of packets in flow, it takes
	// 2 first bits from uint16,
	// time of last packet is stored in seconds and
	// takes 14 last bits of uint16
	flowTable           [size]uint16
	numOfFlows          = int32(1)
	numOfOnePktFlows    = int32(0)
	packetsWithSmallIAT = int64(0) // number of packets with small
	// inter-arrival time (less than iatValueNanos)
	allPackets = int64(1)
	lastTime   = time.Now().UnixNano() // time of last handled packet
	isDdos     uint32
)

func flowHash(srcAddr []byte, srcAddrLen int, srcPort uint32) uint32 {
	h := fnv.New32()
	h.Write(srcAddr)
	return (h.Sum32() + srcPort) & (size - 1)
}

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

// Main function for constructing packet processing graph.
func main() {
	flag.IntVar(&outPort, "outPort", 0, "port to send")
	flag.IntVar(&inPort, "inPort", 0, "port to receive")
	flag.Parse()

	// Init YANFF system at requested number of cores.
	config := flow.Config{
		CPUList: "0-15",
	}

	CheckFatal(flow.SystemInit(&config))

	inputFlow, err := flow.SetReceiver(uint8(inPort))
	CheckFatal(err)
	CheckFatal(flow.SetHandlerDrop(inputFlow, handle, nil))
	CheckFatal(flow.SetSender(inputFlow, uint8(outPort)))
	// Var isDdos is calculated in separate goroutine.
	go calculateMetrics()
	// Begin to process packets.
	CheckFatal(flow.SystemStart())
}

func getPacketHash(pkt *packet.Packet) uint32 {
	var pktTCP *packet.TCPHdr
	var pktUDP *packet.UDPHdr
	var pktICMP *packet.ICMPHdr
	var srcAddr []byte
	var srcAddrLen int
	var srcPort uint32

	pktIPv4, pktIPv6, _ := pkt.ParseAllKnownL3()
	if pktIPv4 != nil {
		pktTCP, pktUDP, pktICMP = pkt.ParseAllKnownL4ForIPv4()
		srcAddr = []byte{byte(pktIPv4.SrcAddr), byte(pktIPv4.SrcAddr >> 8), byte(pktIPv4.SrcAddr >> 16), byte(pktIPv4.SrcAddr >> 24)}
		srcAddrLen = common.IPv4AddrLen
	} else if pktIPv6 != nil {
		pktTCP, pktUDP, pktICMP = pkt.ParseAllKnownL4ForIPv6()
		srcAddr = pktIPv6.SrcAddr[:]
		srcAddrLen = common.IPv6AddrLen
	}

	if pktTCP != nil {
		srcPort = uint32(pktTCP.SrcPort)
	} else if pktUDP != nil {
		srcPort = uint32(pktUDP.SrcPort)
	} else if pktICMP != nil {
		srcPort = uint32(pktICMP.Type)
	}
	return flowHash(srcAddr, srcAddrLen, srcPort)
}

func timeTo14BitSecFrom64BitNanosec(timeNanos int64) uint16 {
	return uint16((timeNanos >> timeShiftToGetSeconds) & timeStampMask)
}

// num of packets in flow can be 0, 1, 2
// 2 means more than one
const (
	zeroPkts = uint16(0)
	onePkt   = uint16(1)
	manyPkts = uint16(2)
)

func setFlowData(time uint16, pkts uint16) uint16 {
	// 1st 2 bits of time are 0 (time takes 14 last bits)
	// pkts can be 0, 1, 2 so we can xor to set them
	return time | pkts<<bitsForTime
}

func getNumOfPkts(flow uint16) uint16 {
	// appy mask '1100000000000000' and shift
	// to get first 2 bits
	return (flow & getNumOfPacketsMask) >> bitsForTime
}

func getTimestamp(flow uint16) uint16 {
	// apply mask '0011111111111111'
	// to get last 14 bits of time
	return flow & timeStampMask
}

func handle(pkt *packet.Packet, context flow.UserContext) bool {
	currentTime := time.Now().UnixNano()
	if currentTime-lastTime < iatValueNanos {
		atomic.AddInt64(&packetsWithSmallIAT, 1)
	}
	atomic.StoreInt64(&lastTime, currentTime)
	atomic.AddInt64(&allPackets, 1)
	currentTime14BitSeconds := timeTo14BitSecFrom64BitNanosec(currentTime)

	hash := getPacketHash(pkt)
	flow := flowTable[hash]
	flowPktNum := getNumOfPkts(flow)
	lastFlowTime := getTimestamp(flow)
	if flowPktNum == zeroPkts {
		// no such record in table
		atomic.AddInt32(&numOfFlows, 1)
		atomic.AddInt32(&numOfOnePktFlows, 1)
		flow = setFlowData(currentTime14BitSeconds, onePkt)
	} else {
		// if flow is expired
		if currentTime14BitSeconds-lastFlowTime > monitoringWindow {
			if flowPktNum != 1 {
				// was multiple packets, now will be one, change counter
				atomic.AddInt32(&numOfOnePktFlows, 1)
			}
			flowPktNum = 0
			flow = setFlowData(currentTime14BitSeconds, onePkt)
		} else {
			if flowPktNum == 1 {
				// was 1 pkt flow, now is not, change counter
				atomic.AddInt32(&numOfOnePktFlows, -1)
			}
			flow = setFlowData(currentTime14BitSeconds, manyPkts)
		}
	}
	flowTable[hash] = flow
	// isDdos without atomic for its not critical
	// if we read wrong value, but speed is important
	if flowPktNum == 0 && isDdos == 1 {
		return false
	}
	return true
}

func calculateMetrics() {
	// every ddosCalculationInterval metrics are
	// compared to threshold values and isDdos status
	// is updated
	for {
		// no atomics, we can get a bit outdated data, not critical
		if float64(packetsWithSmallIAT)/float64(allPackets) >= iatThreshold || float64(numOfOnePktFlows)/float64(numOfFlows) >= ppfThreshold {
			atomic.StoreUint32(&isDdos, 1)
		} else {
			atomic.StoreUint32(&isDdos, 0)
		}
		time.Sleep(ddosCalculationInterval)
	}
}
