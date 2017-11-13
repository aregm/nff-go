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
	"sync/atomic"
	"time"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

const (
	monitoringWindow       = 6                       // 6s - expiration time of flow in a table
	size2InPow             = 29                      // 2**29 will be size of a table
	size                   = uint32(1 << size2InPow) // table size
	iatThreshold           = float64(0.9)
	ppfThreshold           = float64(0.8)
	p                      = uint32(16777619)   // used for hash calculation
	hashInit               = uint32(2166136261) // used for hash calculation
	timeStampMask          = ((1 << 14) - 1)    // 14 first bits mask for timestamp
	getNumOfPacketsMask    = (3 << 14)          // 2 last bits mask for num of packets
	setNumOfPacketsTo1Mask = (1 << 14)          // first 2 bits set to 01 (means 1 pkt)
	setNumOfPacketsTo2Mask = (2 << 14)          // first 2 bits set to 10 (means 1+ pkt)
	timeShiftToGetSeconds  = 30                 // pow(2, 30) is approximately 1e9
	interval200usToNanos   = 200000             // 200 us converted to nanoseconds
)

var (
	inport  int
	outport int
	// flowTable stores number of packets in flow, it takes
	// 2 first bits from uint16,
	// time of last packet is stored in seconds and
	// takes 14 last bits of uint16
	flowTable              [size]uint16
	numOfFlows             = int32(1)
	numOfOnePktFlows       = int32(0)
	packetsInInterval200us = int64(0)
	allPackets             = int64(1)
	lastTime               = time.Now().UnixNano()
	isDdos                 uint32
)

func flowHash(srcAddr []byte, srcAddrLen int, srcPort uint32) uint32 {
	hash := hashInit
	for i := 0; i < srcAddrLen; i++ {
		hash = (hash ^ uint32(srcAddr[i])) * p
	}
	hash += srcPort
	hash += hash << 13
	hash ^= hash >> 7
	hash += hash << 3
	hash ^= hash >> 17
	hash += hash << 5
	return hash & (size - 1)
}

// Main function for constructing packet processing graph.
func main() {
	flag.IntVar(&outport, "outport", 0, "port for sender")
	flag.IntVar(&inport, "inport", 0, "port for receiver")
	flag.Parse()
	// Init YANFF system at requested number of cores.
	config := flow.Config{
		CPUList: "0-15",
	}
	flow.SystemInit(&config)

	inputFlow1 := flow.SetReceiver(inport)
	flow.SetHandler(inputFlow1, handle, nil)
	flow.SetSender(inputFlow1, outport)
	go calculateMetrics()
	// Begin to process packets.
	flow.SystemStart()
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

func handle(pkt *packet.Packet, context flow.UserContext) bool {
	currentTime := time.Now().UnixNano()
	if currentTime-lastTime < interval200usToNanos {
		atomic.AddInt64(&packetsInInterval200us, 1)
	}
	atomic.StoreInt64(&lastTime, currentTime)
	atomic.AddInt64(&allPackets, 1)
	currentTime14BitSeconds := uint16((currentTime >> timeShiftToGetSeconds) & timeStampMask)

	hash := getPacketHash(pkt)
	flow := flowTable[hash]
	flowPktNum := (flow & getNumOfPacketsMask) >> 14
	lastFlowTime := (flow & timeStampMask)
	if flowPktNum == 0 {
		// no such record in table
		atomic.AddInt32(&numOfFlows, 1)
		atomic.AddInt32(&numOfOnePktFlows, 1)
		flow = currentTime14BitSeconds | setNumOfPacketsTo1Mask
	} else {
		// if flow is expired
		if currentTime14BitSeconds-lastFlowTime > monitoringWindow {
			if flowPktNum != 1 {
				// was multiple packets, now will be one, change counter
				atomic.AddInt32(&numOfOnePktFlows, 1)
			}
			flowPktNum = 0
			flow = currentTime14BitSeconds | setNumOfPacketsTo1Mask
		} else {
			if flowPktNum == 1 {
				// was 1 pkt flow, now is not, change counter
				atomic.AddInt32(&numOfOnePktFlows, -1)
			}
			flow = currentTime14BitSeconds | setNumOfPacketsTo2Mask
		}
	}

	flowTable[hash] = flow
	if flowPktNum == 0 && isDdos == 1 {
		return false
	}
	return true
}

func calculateMetrics() {
	for {
		if float64(packetsInInterval200us)/float64(allPackets) >= iatThreshold || float64(numOfOnePktFlows)/float64(numOfFlows) >= ppfThreshold {
			atomic.StoreUint32(&isDdos, 1)
		} else {
			atomic.StoreUint32(&isDdos, 0)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
