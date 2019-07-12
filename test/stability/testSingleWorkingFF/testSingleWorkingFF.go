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

// testScenario=1:
// Firstly packets are generated with different UDP destination addresses,
// filled with IPv4 and UDP checksums and sent to 0 port.
// Secondly packets are received on 0 and 1 ports, verified and calculated.
// Expects to get exact proportion of input packets.
//
// testScenario=2:
// Packets are received on 0 port (from first part), divided according to testType
// and sent back for checking.
//
// testScenario=0:
// Combination of above parts at one machine. Is used by go test.
// Packets are generated, divided and calculated in the same pipeline.

const (
	gotest uint = iota
	generatePart
	receivePart
)

const (
	separate uint = iota
	vseparate
	split
	vsplit
	partition
	vpartition
	pcopy
	handles
	handle
	vhandle
	dhandle
	vdhandle
)

const vecSize = 32

var (
	totalPackets     uint64
	userTotalPackets uint64 = 10000000
	payloadSize      uint   = 16
	speed            uint64 = 1000000

	recvPacketsGroup1 uint64
	recvPacketsGroup2 uint64
	count             uint64
	countRes          uint64
	recvPackets       uint64
	brokenPackets     uint64

	dstPort1 uint16 = 111
	dstPort2 uint16 = 222
	dstPort3 uint16 = 333

	testDoneEvent *sync.Cond
	progStart     time.Time

	// T second timeout is used to let generator reach required speed
	// During timeout packets are skipped and not counted
	T = 10 * time.Second

	outport1     uint
	outport2     uint
	inport1      uint
	inport2      uint
	dpdkLogLevel = "--log-level=0"

	fixMACAddrs  func(*packet.Packet, flow.UserContext)
	fixMACAddrs1 func(*packet.Packet, flow.UserContext)
	fixMACAddrs2 func(*packet.Packet, flow.UserContext)

	l3Rules     *packet.L3Rules
	gTestType   uint
	lessPercent int
	passedLimit uint64
	delta       int = 2
	checkSlice  []uint8
	shift       uint64
)

type packetData struct {
	F1, F2 uint64
}

func main() {
	var testScenario uint
	var testType uint
	flag.UintVar(&testScenario, "testScenario", 0, "1 to use 1 as GENERATE part, 2 to use as RECEIVE part, 0 to use as ONE-MACHINE variant")
	flag.UintVar(&testType, "testType", 0, "0 - Separate test, 1 - Split test, 2 - Partition test, 3 - pCopy test, 4 - Handle test, 5 - DHandle test")
	flag.Uint64Var(&speed, "speed", speed, "speed of generator, Pkts/s")
	flag.UintVar(&outport1, "outport1", 0, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	flag.UintVar(&inport1, "inport1", 0, "port for 1st receiver")
	flag.UintVar(&inport2, "inport2", 1, "port for 2nd receiver")
	flag.Uint64Var(&userTotalPackets, "number", userTotalPackets, "total number of packets to receive by test")
	flag.DurationVar(&T, "timeout", T, "test start delay, needed to stabilize speed. Packets sent during timeout do not affect test result")
	configFile := flag.String("config", "", "Specify json config file name (mandatory for VM)")
	target := flag.String("target", "", "Target host name from config file (mandatory for VM)")
	flag.StringVar(&dpdkLogLevel, "dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()

	if err := initDPDK(); err != nil {
		fmt.Printf("fail: %+v\n", err)
	}
	if err := executeTest(*configFile, *target, testScenario, testType); err != nil {
		fmt.Printf("fail: %+v\n", err)
	}
}

func initDPDK() error {
	// Init NFF-GO system
	config := flow.Config{
		DPDKArgs: []string{dpdkLogLevel},
	}
	if err := flow.SystemInit(&config); err != nil {
		return err
	}
	return nil
}

func executeTest(configFile, target string, testScenario uint, testType uint) error {
	if testScenario > 3 || testScenario < 0 {
		return errors.New("testScenario should be in interval [0, 3]")
	}
	gTestType = testType
	countRes = 0
	recvPacketsGroup1 = 0
	recvPacketsGroup2 = 0
	recvPackets = 0
	count = 0
	brokenPackets = 0

	checkSlice = make([]uint8, userTotalPackets*2, userTotalPackets*2)

	stabilityCommon.InitCommonState(configFile, target)
	fixMACAddrs = stabilityCommon.ModifyPacket[0].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs1 = stabilityCommon.ModifyPacket[0].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs2 = stabilityCommon.ModifyPacket[1].(func(*packet.Packet, flow.UserContext))

	if err := setParameters(testScenario); err != nil {
		return err
	}

	if testScenario == receivePart {
		inputFlow, err := flow.SetReceiver(uint16(inport1))
		if err != nil {
			return err
		}

		if err := flow.SetHandlerDrop(inputFlow, checkShouldBeSkipped, nil); err != nil {
			return err
		}

		var flow1, flow2 *flow.Flow
		if flow1, flow2, err = setMainTest(inputFlow); err != nil {
			return err
		}

		// Send each flow to corresponding port. Send queues will be added automatically.
		if err := flow.SetSender(flow1, uint16(outport1)); err != nil {
			return err
		}
		if testType < handles {
			if err := flow.SetSender(flow2, uint16(outport2)); err != nil {
				return err
			}
		}

		// Begin to process packets.
		if err := flow.SystemStart(); err != nil {
			return err
		}
	}

	if testScenario == generatePart || testScenario == gotest {
		var m sync.Mutex
		testDoneEvent = sync.NewCond(&m)

		// Create packet flow
		generatedFlow, _, err := flow.SetFastGenerator(generatePacket, speed, nil)
		if err != nil {
			return err
		}

		var flow1, flow2 *flow.Flow
		if testScenario == generatePart {
			if err := flow.SetSender(generatedFlow, uint16(outport1)); err != nil {
				return err
			}

			// Create receiving flows and set a checking function for it
			flow1, err = flow.SetReceiver(uint16(inport1))
			if err != nil {
				return err
			}
			if testType < handles {
				flow2, err = flow.SetReceiver(uint16(inport2))
				if err != nil {
					return err
				}
			}
		}
		if testScenario == gotest {
			if flow1, flow2, err = setMainTest(generatedFlow); err != nil {
				return err
			}
		}
		if err := flow.SetHandlerDrop(flow1, checkInputFlow1, nil); err != nil {
			return err
		}
		if err := flow.SetStopper(flow1); err != nil {
			return err
		}
		if testType < handles {
			if err := flow.SetHandlerDrop(flow2, checkInputFlow2, nil); err != nil {
				return err
			}
			if err := flow.SetStopper(flow2); err != nil {
				return err
			}
		}

		progStart = time.Now()
		// Start pipeline
		go func() {
			err = flow.SystemStart()
		}()
		if err != nil {
			return err
		}

		// Wait for enough packets to arrive
		testDoneEvent.L.Lock()
		testDoneEvent.Wait()
		testDoneEvent.L.Unlock()
		flow.SystemStop()
		return composeStatistics()
	}
	return nil
}

func setParameters(testScenario uint) (err error) {
	passedLimit = 98
	shift = 0
	totalPackets = userTotalPackets
	switch gTestType {
	case separate, vseparate:
		if testScenario != generatePart {
			l3Rules, err = packet.GetL3ACLFromTextTable("test-separate-l3rules.conf")
		}
		// Test expects to receive 33% of packets on 0 port and 66% on 1 port
		lessPercent = 33
		shift = 1
	case split, vsplit:
		if testScenario != generatePart {
			l3Rules, err = packet.GetL3ACLFromTextTable("test-split.conf")
		}
		// Test expects to receive 20% of packets on 0 port and 80% on 1 port
		lessPercent = 20
	case partition, vpartition:
		// Test expects to receive 10% of packets on 0 port and 90% on 1 port
		lessPercent = 10
	case pcopy:
		// Test expects to receive 50% of packets on 0 port and 50% on 1 port (200% total)
		lessPercent = 50
		passedLimit = 196 // ~98 * 2
	case handle, vhandle:
		// Test expects to receive 100% of packets on 0 port and 0% on 1 port
		lessPercent = 100
		shift = 3
	case dhandle, vdhandle:
		if testScenario != generatePart {
			l3Rules, err = packet.GetL3ACLFromTextTable("test-handle-l3rules.conf")
		}
		// Test expects to receive 100% of packets on 0 port and 0% on 1 port (33% total)
		lessPercent = 100
		passedLimit = 31 // 98 * 0.33
		totalPackets = totalPackets / 3
		shift = 4
	}
	return err
}

func setMainTest(inFlow *flow.Flow) (*flow.Flow, *flow.Flow, error) {
	var flow2 *flow.Flow
	var err error
	switch gTestType {
	case separate:
		// Separate packet flow based on ACL.
		flow2, err = flow.SetSeparator(inFlow, l3Separator, nil)
	case split, vsplit:
		// Split packet flow based on ACL.
		var splittedFlows []*flow.Flow
		if gTestType == split {
			splittedFlows, err = flow.SetSplitter(inFlow, l3Splitter, 3, nil)
		} else {
			splittedFlows, err = flow.SetVectorSplitter(inFlow, vectorL3Splitter, 3, nil)
		}
		// "0" flow is used for dropping packets without sending them.
		if err1 := flow.SetStopper(splittedFlows[0]); err1 != nil {
			return nil, nil, err1
		}
		inFlow = splittedFlows[1]
		flow2 = splittedFlows[2]
	case partition:
		// Parition flow
		flow2, err = flow.SetPartitioner(inFlow, 100, 1000)
	case pcopy:
		flow2, err = flow.SetCopier(inFlow)
	case handle:
		err = flow.SetHandler(inFlow, l3Handler, nil)
	case dhandle:
		err = flow.SetHandlerDrop(inFlow, l3dHandler, nil)
	case vseparate:
		// Separate packet flow based on ACL.
		flow2, err = flow.SetVectorSeparator(inFlow, vectorL3Separator, nil)
	case vpartition:
		// We need vector handler to switch to vector mode
		err = flow.SetVectorHandler(inFlow, vectorL3Handler, nil)
		if err != nil {
			return nil, nil, err
		}
		flow2, err = flow.SetPartitioner(inFlow, 100, 1000)
	case vhandle:
		err = flow.SetVectorHandler(inFlow, vectorL3Handler, nil)
	case vdhandle:
		err = flow.SetVectorHandlerDrop(inFlow, vectorL3dHandler, nil)
	}
	if err != nil {
		return nil, nil, err
	}

	if err = flow.SetHandler(inFlow, fixPackets1, nil); err != nil {
		return nil, nil, err
	}
	if gTestType < handles {
		if err = flow.SetHandler(flow2, fixPackets2, nil); err != nil {
			return nil, nil, err
		}
	}
	return inFlow, flow2, err
}

func composeStatistics() error {
	// Compose statistics
	sent := atomic.LoadUint64(&countRes)

	recv1 := atomic.LoadUint64(&recvPacketsGroup1)
	recv2 := atomic.LoadUint64(&recvPacketsGroup2)
	received := recv1 + recv2

	broken := atomic.LoadUint64(&brokenPackets)

	var p1 int
	var p2 int
	if received != 0 {
		p1 = int(recv1 * 100 / received)
		p2 = int(recv2 * 100 / received)
	}

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")
	println("Ratio =", received*100/sent, "%")
	println("On port", inport1, "received=", recv1, "packets")
	println("On port", inport2, "received=", recv2, "packets")
	println("Proportion of packets received on", inport1, "port =", p1, "%")
	println("Proportion of packets received on", inport2, "port =", p2, "%")
	println("Broken = ", broken, "packets")

	// Test is passed, if p1 is ~lessPercent% and p2 is ~100 - lessPercent%
	// and if total receive/send rate is high
	if broken == 0 &&
		p1 <= lessPercent+delta && p2 <= 100-lessPercent+delta &&
		p1 >= lessPercent-delta && p2 >= 100-lessPercent-delta && received*100/sent > passedLimit {
		println("TEST PASSED")
		return nil
	}
	println("TEST FAILED")
	return errors.New("final statistics check failed")
}

// Function to use in generator
func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		log.Fatal("Failed to create new packet")
	}
	if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
		log.Fatal("Failed to create new packet")
	}
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()

	if gTestType == separate || gTestType == dhandle || gTestType == vseparate || gTestType == vdhandle {
		// Generate packets of 3 groups
		if count%3 == 0 {
			udp.DstPort = packet.SwapBytesUint16(dstPort1)
		} else if count%3 == 1 {
			udp.DstPort = packet.SwapBytesUint16(dstPort2)
		} else {
			udp.DstPort = packet.SwapBytesUint16(dstPort3)
		}
	} else if gTestType == split || gTestType == vsplit {
		// Generate packets of 2 groups
		if count%5 == 0 {
			udp.DstPort = packet.SwapBytesUint16(dstPort1)
		} else {
			udp.DstPort = packet.SwapBytesUint16(dstPort2)
		}
	} else {
		// Generate identical packets
		udp.DstPort = packet.SwapBytesUint16(dstPort1)
	}

	// Put a unique non-zero value
	ptr := (*packetData)(pkt.Data)
	ptr.F2 = 2

	// We do not consider the start time of the system in this test
	if time.Since(progStart) >= T && atomic.LoadUint64(&recvPackets) < totalPackets {
		atomic.AddUint64(&countRes, 1)
		ptr.F2 = 7
	}
	ptr.F1 = countRes + 1

	// Put checksums
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))
	fixMACAddrs(pkt, context)
	atomic.AddUint64(&count, 1)
}

func checkShouldBeSkipped(pkt *packet.Packet, context flow.UserContext) bool {
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return false
	}
	return true
}

func checkInputFlow1(pkt *packet.Packet, context flow.UserContext) bool {
	if commonCheck(pkt) == false {
		return false
	}
	udp := pkt.GetUDPForIPv4()
	if udp.DstPort != packet.SwapBytesUint16(dstPort1) {
		println("Unexpected packet in inputFlow1", udp.DstPort)
		atomic.AddUint64(&brokenPackets, 1)
		return false
	}
	atomic.AddUint64(&recvPacketsGroup1, 1)
	return true
}

func checkInputFlow2(pkt *packet.Packet, context flow.UserContext) bool {
	if commonCheck(pkt) == false {
		return false
	}
	udp := pkt.GetUDPForIPv4()
	if gTestType == separate &&
		udp.DstPort != packet.SwapBytesUint16(dstPort2) &&
		udp.DstPort != packet.SwapBytesUint16(dstPort3) ||
		gTestType == split &&
			udp.DstPort != packet.SwapBytesUint16(dstPort2) ||
		(gTestType == partition || gTestType == vpartition || gTestType == pcopy) &&
			udp.DstPort != packet.SwapBytesUint16(dstPort1) {
		println("Unexpected packet in inputFlow2", udp.DstPort)
		atomic.AddUint64(&brokenPackets, 1)
		return false
	}
	atomic.AddUint64(&recvPacketsGroup2, 1)
	return true
}

func commonCheck(pkt *packet.Packet) bool {
	if time.Since(progStart) < T || stabilityCommon.ShouldBeSkipped(pkt) {
		return false
	}
	if atomic.AddUint64(&recvPackets, 1) > totalPackets {
		testDoneEvent.Signal()
		return false
	}

	if pkt.ParseData() < 0 {
		println("ParseData returned negative value")
		atomic.AddUint64(&brokenPackets, 1)
		return false
	}
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	recvIPv4Cksum := packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	recvUDPCksum := packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))
	ptr := (*packetData)(pkt.Data)
	ptr.F2 -= shift
	if ptr.F1 >= userTotalPackets*2 {
		println("Test generated a number of packet which exceed planned two times")
		return false
	}
	if recvIPv4Cksum != ipv4.HdrChecksum || recvUDPCksum != udp.DgramCksum ||
		ptr.F2 != 2 && ptr.F2 != 7 ||
		ptr.F2 == 2 && ptr.F1 != 1 ||
		gTestType != pcopy && ptr.F2 == 7 && checkSlice[ptr.F1] != 0 ||
		gTestType == pcopy && ptr.F2 == 7 && checkSlice[ptr.F1] > 1 {
		println("Packet contents are incorrect")
		println(ptr.F2, ptr.F1, checkSlice[ptr.F1], recvIPv4Cksum, recvIPv4Cksum, recvUDPCksum, udp.DgramCksum)
		atomic.AddUint64(&brokenPackets, 1)
		return false
	}
	checkSlice[ptr.F1]++
	return true
}

func l3Separator(pkt *packet.Packet, context flow.UserContext) bool {
	// Return whether packet is accepted.
	addF2(pkt)
	return pkt.L3ACLPermit(l3Rules)
}

func vectorL3Separator(pkts []*packet.Packet, mask *[vecSize]bool, answers *[vecSize]bool, context flow.UserContext) {
	// Return whether packet is accepted.
	for i := 0; i < vecSize; i++ {
		if (*mask)[i] == true {
			addF2(pkts[i])
			answers[i] = pkts[i].L3ACLPermit(l3Rules)
		}
	}
}

func l3Splitter(pkt *packet.Packet, context flow.UserContext) uint {
	// Return number of flow to which put this packet. Based on ACL rules.
	return pkt.L3ACLPort(l3Rules)
}

func vectorL3Splitter(pkts []*packet.Packet, mask *[vecSize]bool, answers *[vecSize]uint8, context flow.UserContext) {
	// Return number of flow to which put this packet. Based on ACL rules.
	for i := 0; i < vecSize; i++ {
		if (*mask)[i] == true {
			answers[i] = uint8(pkts[i].L3ACLPort(l3Rules))
		}
	}
}

func l3Handler(pkt *packet.Packet, context flow.UserContext) {
	addF2(pkt)
}

func vectorL3Handler(pkts []*packet.Packet, mask *[vecSize]bool, context flow.UserContext) {
	for i := uint(0); i < vecSize; i++ {
		if (*mask)[i] == true {
			addF2(pkts[i])
		}
	}
}

func l3dHandler(pkt *packet.Packet, context flow.UserContext) bool {
	addF2(pkt)
	return pkt.L3ACLPermit(l3Rules)
}

func vectorL3dHandler(pkts []*packet.Packet, mask *[vecSize]bool, answers *[vecSize]bool, context flow.UserContext) {
	for i := uint(0); i < vecSize; i++ {
		if (*mask)[i] == true {
			addF2(pkts[i])
			answers[i] = pkts[i].L3ACLPermit(l3Rules)
		}
	}
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

func addF2(pkt *packet.Packet) {
	pkt.ParseData()
	ptr := (*packetData)(pkt.Data)
	ptr.F2 += shift
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))
}
