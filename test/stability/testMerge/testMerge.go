// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/test/stability/stabilityCommon"
)

// Test with testScenario=1:
// This part of test generates packets sends on 2 ports and receives packets
// on 1 port (merged by second part). Checks quantity and contents of packets according to scenario.
//
// Test with testScenario=2:
// This part of test receives packets on 2 ports, merges flowsж
// and sends result flow to 1 port. There are several scenarios:
// 0: getGet - get packets, merge and send back
// 1: segmGet - add segment function to one flow, merge and send
// 2: multipleSegm - add segment functions at both flows, merge and send
// 3: singleSegm - stop one flow, partition the second, merge and send back
// 4: getCopy - add copier to one flow and merge all
// 5: copyCopy - add copier to both flows and merge all
// 6: segmCopy - split one flow, copy another and stop original, merge copy and two splitted, send
//
// Test with testScenario=0:
// all these actions are made in one pipeline without actual send and receive.

const (
	gotest uint = iota
	generatePart
	receivePart
	useGenerator1 = 0
	useGenerator2 = 1
	partitionN    = 32
	partitionM    = 32
)

var (
	totalPackets uint64 = 100000
	// Payload is 16 byte
	payloadSize uint   = 16
	speed       uint64 = 1000000

	sentPacketsGroup1 uint64
	sentPacketsGroup2 uint64

	recvPacketsGroup1 uint64
	recvPacketsGroup2 uint64

	recvPackets   uint64
	brokenPackets uint64

	// Usually when writing multibyte fields to packet, we should make
	// sure that byte order in packet buffer is correct and swap bytes if needed.
	// Here for testing purposes we use addresses with bytes swapped by hand.
	ipv4addr1 common.IPv4Address = 0x0100007f // 127.0.0.1
	ipv4addr2 common.IPv4Address = 0x05090980 // 128.9.9.5

	testDoneEvent *sync.Cond
	progStart     time.Time

	// T second timeout is used to let generator reach required speed
	// During timeout packets are skipped and not counted
	// TODO: investigate why 20 is needed here instead of 10. (Low send/recv rate with 10)
	T = 20 * time.Second

	outport1     uint
	outport2     uint
	inport1      uint
	inport2      uint
	dpdkLogLevel = "--log-level=0"

	fixMACAddrs  func(*packet.Packet, flow.UserContext)
	fixMACAddrs1 func(*packet.Packet, flow.UserContext)
	fixMACAddrs2 func(*packet.Packet, flow.UserContext)

	passed       int32 = 1
	testScenario uint
)

type payloadVal uint

const (
	notCount payloadVal = iota
	baseGr1
	baseGr2
)

type packetData struct {
	N uint
}

func main() {
	var pipelineType uint
	var addSegmAfterMerge bool
	flag.BoolVar(&addSegmAfterMerge, "addSegmAfterMerge", false, "true to insert handler after merge in pipeline, false(default) otherwise")
	flag.UintVar(&testScenario, "testScenario", 0, "1 to use 1st part scenario, 2 snd, 0 to use one-machine test")
	flag.UintVar(&pipelineType, "pipelineType", 0, "merge between different ff types 0: getGet, 1: segmGet, 2: multipleSegm , 3: singleSegm, 4: getCopy, 5: copyCopy, 6: segmCopy")
	flag.Uint64Var(&speed, "speed", speed, "speed of 1 and 2 generators, Pkts/s")
	flag.UintVar(&outport1, "outport1", 0, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	flag.UintVar(&inport1, "inport1", 0, "port for 1st receiver")
	flag.UintVar(&inport2, "inport2", 1, "port for 2nd receiver")
	flag.Uint64Var(&totalPackets, "number", totalPackets, "total number of packets to receive by test")
	flag.DurationVar(&T, "timeout", T, "test start delay, needed to stabilize speed. Packets sent during timeout do not affect test result")
	configFile := flag.String("config", "", "Specify json config file name (mandatory for VM)")
	target := flag.String("target", "", "Target host name from config file (mandatory for VM)")
	flag.StringVar(&dpdkLogLevel, "dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()
	flow.CheckFatal(initDPDK())
	flow.CheckFatal(executeTest(*configFile, *target, testScenario, pipelineScenario(pipelineType), addSegmAfterMerge))
}

// getter - is a part of pipeline getting packets by receive or generate or fast generate
type getScenario uint

const (
	fastGenerate getScenario = iota
	recv
)

func setGetter(scenario getScenario, inputSource uint) (finalFlow *flow.Flow, err error) {
	switch scenario {
	case recv:
		finalFlow, err = flow.SetReceiver(uint16(inputSource))
	case fastGenerate:
		if inputSource == useGenerator1 {
			finalFlow, err = flow.SetFastGenerator(generatePacketGroup, speed, &generatorParameters{isGroup1: true})
		} else if inputSource == useGenerator2 {
			finalFlow, err = flow.SetFastGenerator(generatePacketGroup, speed, &generatorParameters{isGroup1: false})
		} else {
			return nil, errors.New(" setGetter: unknown generator type")
		}
	default:
		return nil, errors.New(" setGetter: unknown generator type")
	}
	return finalFlow, err
}

func handlePackets(pkt *packet.Packet, context flow.UserContext) {
}

// different test cases
type pipelineScenario uint

const (
	getGet pipelineScenario = iota
	segmGet
	multipleSegm
	singleSegm
	getCopy
	copyCopy
	segmCopy
)

func buildPipeline(scenario pipelineScenario, firstFlow, secondFlow *flow.Flow) (*flow.Flow, error) {
	var err error
	switch scenario {
	// simplest case - two getters are merged
	case getGet:
	// segment merged with getter
	case segmGet:
		if err := flow.SetHandler(firstFlow, handlePackets, nil); err != nil {
			return nil, err
		}
	// two segments merged
	case multipleSegm:
		if err := flow.SetHandler(firstFlow, handlePackets, nil); err != nil {
			return nil, err
		}
		if err := flow.SetHandler(secondFlow, handlePackets, nil); err != nil {
			return nil, err
		}
	// flow is splitted and then merged
	case singleSegm:
		if err := flow.SetStopper(secondFlow); err != nil {
			return nil, err
		}
		secondFlow, err = flow.SetPartitioner(firstFlow, partitionN, partitionM)
		if err != nil {
			return nil, err
		}
	// getter merged with copy
	case getCopy:
		copiedFlow, err := flow.SetCopier(firstFlow)
		if err != nil {
			return nil, err
		}
		return flow.SetMerger(firstFlow, secondFlow, copiedFlow)
	// 2 copiers
	case copyCopy:
		copiedFlow1, err := flow.SetCopier(firstFlow)
		if err != nil {
			return nil, err
		}
		copiedFlow2, err := flow.SetCopier(secondFlow)
		if err != nil {
			return nil, err
		}
		return flow.SetMerger(firstFlow, secondFlow, copiedFlow1, copiedFlow2)
	// segmend merged with copy
	case segmCopy:
		splittedFlow, err := flow.SetPartitioner(firstFlow, partitionN, partitionM)
		if err != nil {
			return nil, err
		}
		copiedFlow, err := flow.SetCopier(secondFlow)
		if err != nil {
			return nil, err
		}
		err = flow.SetStopper(secondFlow)
		if err != nil {
			return nil, err
		}
		return flow.SetMerger(firstFlow, splittedFlow, copiedFlow)
	}
	return flow.SetMerger(firstFlow, secondFlow)
}

// test body
func setTestingPart(scenario pipelineScenario, addSegmAfterMerge bool) error {
	var (
		input1, input2 uint
		m              sync.Mutex
		checkedFlow    *flow.Flow
		err            error
		getter         getScenario
	)
	if testScenario != receivePart {
		testDoneEvent = sync.NewCond(&m)
		input1 = useGenerator1
		input2 = useGenerator2
		getter = fastGenerate
	} else {
		input1 = inport1
		input2 = inport2
		getter = recv
	}
	firstFlow, err := setGetter(getter, input1)
	if err != nil {
		return err
	}
	secondFlow, err := setGetter(getter, input2)
	if err != nil {
		return err
	}
	if testScenario != generatePart {
		checkedFlow, err = buildPipeline(scenario, firstFlow, secondFlow)
		if err != nil {
			return err
		}
		// add segment to pipeline after merge function
		if addSegmAfterMerge {
			if err := flow.SetHandler(checkedFlow, handlePackets, nil); err != nil {
				return err
			}
		}
	} else {
		if err := flow.SetSender(firstFlow, uint16(outport1)); err != nil {
			return err
		}
		if err := flow.SetSender(secondFlow, uint16(outport2)); err != nil {
			return err
		}
		checkedFlow, err = setGetter(recv, inport1)
		if err != nil {
			return err
		}
	}
	if testScenario != receivePart {
		if err := flow.SetHandler(checkedFlow, checkPackets, nil); err != nil {
			return err
		}
		if err := flow.SetStopper(checkedFlow); err != nil {
			return err
		}
	} else {
		if err := flow.SetHandler(checkedFlow, fixPackets, nil); err != nil {
			return err
		}
		if err := flow.SetSender(checkedFlow, uint16(outport1)); err != nil {
			return err
		}
	}
	if testScenario == receivePart {
		return flow.SystemStart()
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

	return composeStatistics(scenario)
}

// stop system and reset test counters
func resetState() {
	flow.SystemStop()

	sentPacketsGroup1 = 0
	sentPacketsGroup2 = 0

	recvPacketsGroup1 = 0
	recvPacketsGroup2 = 0

	recvPackets = 0
	brokenPackets = 0

	passed = 1
}

// Init NFF-GO system
func initDPDK() error {
	config := flow.Config{
		DPDKArgs: []string{dpdkLogLevel},
	}
	return flow.SystemInit(&config)
}

func executeTest(configFile, target string, testScenario uint, scenario pipelineScenario, addSegmAfterMerge bool) error {
	if testScenario > 3 || testScenario < 0 {
		return errors.New("testScenario should be in interval [0, 3]")
	}
	stabilityCommon.InitCommonState(configFile, target)

	fixMACAddrs1 = stabilityCommon.ModifyPacket[0].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs2 = stabilityCommon.ModifyPacket[1].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs = stabilityCommon.ModifyPacket[0].(func(*packet.Packet, flow.UserContext))
	return setTestingPart(scenario, addSegmAfterMerge)
}

func failCheck(msg string) error {
	println(msg)
	println("TEST FAILED")
	return errors.New(msg)
}

func composeStatistics(scenario pipelineScenario) error {
	maxBroken := totalPackets / 10
	passedLimit := uint64(98)
	lessPercent := 50
	eps := 2
	var sent1, sent2, shouldGet1, shouldGet2 uint64
	sent1 = atomic.LoadUint64(&sentPacketsGroup1)
	sent2 = atomic.LoadUint64(&sentPacketsGroup2)
	shouldGet1 = sent1
	shouldGet2 = sent2
	switch scenario {
	case singleSegm:
		shouldGet2 = 0
		lessPercent = 100
		eps = 0
	case getCopy:
		shouldGet1 *= 2
		lessPercent = 66
		eps = 4
	case copyCopy:
		shouldGet1 *= 2
		shouldGet2 *= 2
	}

	recv1 := atomic.LoadUint64(&recvPacketsGroup1)
	recv2 := atomic.LoadUint64(&recvPacketsGroup2)

	received := recv1 + recv2
	if received == 0 {
		return failCheck("received 0 packets, error!")
	}
	// Proportions of 1 and 2 packet in received flow
	p1 := int(recv1 * 100 / received)
	p2 := int(recv2 * 100 / received)
	broken := atomic.LoadUint64(&brokenPackets)

	// Print report
	println("=================================")
	println("Sent total:", sent1+sent2, "packets")
	println("generated group 1", sent1, "packets")
	println("generated group 2", sent2, "packets")
	println("=================================")
	println("should get group 1", shouldGet1, "packets")
	println("should get group 2", shouldGet2, "packets")
	println("=================================")
	println("Received total:", received, "packets")
	println("got group 1", recv1, "packets")
	println("got group 2", recv2, "packets")
	println("=================================")

	var ratio1, ratio2 uint64
	if shouldGet1 != 0 {
		ratio1 = recv1 * 100 / shouldGet1
	} else {
		if recv1 != 0 {
			return failCheck("lost all packets from group 1")
		}
	}
	if shouldGet2 != 0 {
		ratio2 = recv2 * 100 / shouldGet2
	} else {
		if recv2 != 0 {
			return failCheck("lost all packets from group 2")
		}
	}
	println("Group1 ratio =", ratio1, "%")
	println("Group2 ratio =", ratio2, "%")

	println("Group1 proportion in received flow =", p1, "%")
	println("Group2 proportion in received flow =", p2, "%")

	println("Broken = ", broken, "packets")

	if broken > maxBroken {
		return failCheck("too many broken packets")
	}

	if atomic.LoadInt32(&passed) != 0 && received*100/(shouldGet1+shouldGet2) >= passedLimit {
		// Test is passed, if p1 and p2 do not differ too much: |p1-p2| < 4%
		// and enough packets received back
		if p1 <= lessPercent+eps && p2 <= 100-lessPercent+eps &&
			p1 >= lessPercent-eps && p2 >= 100-lessPercent-eps {
			println("TEST PASSED")
			return nil
		}
	}
	return failCheck("final statistics check failed")
}

func fixPackets(pkt *packet.Packet, ctx flow.UserContext) {
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	fixMACAddrs(pkt, ctx)
}

type generatorParameters struct {
	isGroup1 bool
}

func (p generatorParameters) Copy() interface{} {
	return p
}

func (p generatorParameters) Delete() {
}

func generatePacketGroup(pkt *packet.Packet, context flow.UserContext) {
	isGroup1 := (context.(generatorParameters)).isGroup1
	if pkt == nil {
		log.Fatal("Failed to create new packet")
	}
	if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
		log.Fatal("Failed to init empty packet")
	}
	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	if isGroup1 {
		ipv4.SrcAddr = ipv4addr1
		fixMACAddrs1(pkt, context)
	} else {
		ipv4.SrcAddr = ipv4addr2
		fixMACAddrs2(pkt, context)
	}

	ptr := (*packetData)(pkt.Data)
	ptr.N = uint(notCount)

	// We do not consider the start time of the system in this test
	if time.Since(progStart) >= T && atomic.LoadUint64(&recvPackets) < totalPackets {
		if isGroup1 {
			ptr.N = uint(baseGr1)
			atomic.AddUint64(&sentPacketsGroup1, 1)
		} else {
			ptr.N = uint(baseGr2)
			atomic.AddUint64(&sentPacketsGroup2, 1)
		}
	}

	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))
}

// Count and check packets in received flow
func checkPackets(pkt *packet.Packet, context flow.UserContext) {
	if time.Since(progStart) < T || stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}

	if pkt.ParseData() < 0 {
		println("ParseData returned negative value")
		atomic.AddUint64(&brokenPackets, 1)
		return
	}

	ipv4 := pkt.GetIPv4()
	udp := pkt.GetUDPForIPv4()
	recvIPv4Cksum := packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	recvUDPCksum := packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))
	ptr := (*packetData)(pkt.Data)
	payload := payloadVal(ptr.N)
	if payload == notCount {
		return
	}

	if recvIPv4Cksum != ipv4.HdrChecksum || recvUDPCksum != udp.DgramCksum {
		// Packet is broken
		atomic.AddUint64(&brokenPackets, 1)
		return
	}
	if ipv4.SrcAddr == ipv4addr1 {
		if payload == baseGr1 {
			atomic.AddUint64(&recvPacketsGroup1, 1)
		} else {
			atomic.AddUint64(&brokenPackets, 1)
		}
	} else if ipv4.SrcAddr == ipv4addr2 {
		if payload == baseGr2 {
			atomic.AddUint64(&recvPacketsGroup2, 1)
		} else {
			atomic.AddUint64(&brokenPackets, 1)
		}
	} else {
		println("Packet Ipv4 src addr does not match addr1 or addr2")
		println("TEST FAILED")
		atomic.StoreInt32(&passed, 0)
	}
	if atomic.AddUint64(&recvPackets, 1) >= totalPackets {
		testDoneEvent.Signal()
		return
	}
}
