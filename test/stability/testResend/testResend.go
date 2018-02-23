// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"

	"github.com/intel-go/nff-go/test/stability/stabilityCommon"
	"github.com/intel-go/nff-go/test/stability/testResend/testResendCommon"
)

// Test with testScenario=1:
// generates packets on outport and receives them on
// inport. The test records packet's index inside of the first field
// of the packet and sets the second field to zero. It expects the
// other half of the test to copy index from first part of the packet
// to the second part. When packet is received, test routine compares
// first and second halves and checks that they are equal. Test also
// calculates sent/received ratio and prints it when a predefined
// number of packets is received.
//
// Test with testScenario=2:
// receives packets at inport,
// copies index from first part of the packet to the second part
// and sends to outport.
//
// Test with testScenario=0:
// makes all it in one pipeline without actual send and receive.

var (
	totalPackets uint64 = 10000000

	// Packet should hold two int64 fields
	packetSize uint64 = uint64(unsafe.Sizeof(packetSize) * 2)

	sentPackets     uint64
	receivedPackets uint64
	testDoneEvent   *sync.Cond
	passed          int32 = 1
	progStart       time.Time
	speed           uint64 = 1000000

	// T second timeout is used to let generator reach required speed
	// During timeout packets are skipped and not counted
	T = 10 * time.Second

	outport uint
	inport  uint
	dpdkLogLevel *string

	fixMACAddrs  func(*packet.Packet, flow.UserContext)
	fixMACAddrs1 func(*packet.Packet, flow.UserContext)
)

func main() {
	var testScenario uint
	flag.UintVar(&testScenario, "testScenario", 0, "1 to use 1st part scenario, 2 snd, 0 to use one-machine test")
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport, "inport", 1, "port for receiver")
	flag.Uint64Var(&speed, "speed", speed, "speed of generator")
	flag.Uint64Var(&totalPackets, "number", totalPackets, "total number of packets to receive by test")
	flag.DurationVar(&T, "timeout", T, "test start timeout, time to stabilize speed. Packets sent during timeout do not affect test result")
	configFile := flag.String("config", "", "Specify json config file name (mandatory for VM)")
	target := flag.String("target", "", "Target host name from config file (mandatory for VM)")
	dpdkLogLevel = flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()
	if err := executeTest(*configFile, *target, testScenario); err != nil {
		fmt.Printf("fail: %+v\n", err)
	}
}

func executeTest(configFile, target string, testScenario uint) error {
	if testScenario > 3 || testScenario < 0 {
		return errors.New("testScenario should be in interval [0, 3]")
	}
	// Init NFF-GO system
	config := flow.Config{
		DPDKArgs: []string{ *dpdkLogLevel },
	}

	if err := flow.SystemInit(&config); err != nil { return err }

	stabilityCommon.InitCommonState(configFile, target)
	fixMACAddrs = stabilityCommon.ModifyPacket[outport].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs1 = stabilityCommon.ModifyPacket[outport].(func(*packet.Packet, flow.UserContext))

	if testScenario == 2 {
		inputFlow, err := flow.SetReceiver(uint8(inport))
		if err != nil { return err }
		if err := flow.SetHandler(inputFlow, fixPacket, nil); err != nil { return err }
		if err := flow.SetSender(inputFlow, uint8(outport)); err != nil { return err }

		// Begin to process packets.
		if err := flow.SystemStart(); err != nil { return err }
	} else {
		var m sync.Mutex
		testDoneEvent = sync.NewCond(&m)

		firstFlow, err := flow.SetFastGenerator(generatePacket, speed, nil)
		if err != nil { return err }
		var secondFlow *flow.Flow
		if testScenario == 1 {
			// Send all generated packets to the output
			if err := flow.SetSender(firstFlow, uint8(outport)); err != nil { return err }
			// Create receiving flow and set a checking function for it
			secondFlow, err = flow.SetReceiver(uint8(inport))
			if err != nil { return err }
		} else {
			secondFlow = firstFlow
			if err := flow.SetHandler(secondFlow, fixPacket, nil); err != nil { return err }
		}
		if err := flow.SetHandler(secondFlow, checkPackets, nil); err != nil { return err }
		if err := flow.SetStopper(secondFlow); err != nil { return err }

		// Start pipeline
		go func() {
			err = flow.SystemStart()
		}()
		if err != nil { return err }
		progStart = time.Now()

		// Wait for enough packets to arrive
		testDoneEvent.L.Lock()
		testDoneEvent.Wait()
		testDoneEvent.L.Unlock()
		composeStatistics()
	}
	return nil
}

func composeStatistics() {
	// Compose statistics
	sent := atomic.LoadUint64(&sentPackets)
	received := atomic.LoadUint64(&receivedPackets)
	ratio := received * 100 / sent

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")
	println("Ratio = ", ratio, "%")
	if atomic.LoadInt32(&passed) != 0 {
		println("TEST PASSED")
	} else {
		println("TEST FAILED")
	}
}

func generatePacket(emptyPacket *packet.Packet, context flow.UserContext) {
	if packet.InitEmptyIPv4UDPPacket(emptyPacket, uint(packetSize)) == false {
		fmt.Println("TEST FAILED")
		panic("Failed to init empty packet")
	}

	fixMACAddrs(emptyPacket, context)

	sent := atomic.LoadUint64(&sentPackets)
	ptr := (*testResendCommon.Packetdata)(emptyPacket.Data)

	// Put a unique non-zero value here
	ptr.F1 = sent + 1
	ptr.F2 = 0
	// We do not consider the start time of the system in this test
	if time.Since(progStart) < T {
		return
	}

	atomic.AddUint64(&sentPackets, 1)
}

func checkPackets(pkt *packet.Packet, context flow.UserContext) {
	if time.Since(progStart) < T {
		return
	}
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	newValue := atomic.AddUint64(&receivedPackets, 1)
	pkt.ParseData()
	ptr := (*testResendCommon.Packetdata)(pkt.Data)
	if ptr.F1 != ptr.F2 {
		fmt.Printf("Data mismatch in the packet, read %x and %x\n", ptr.F1, ptr.F2)
		atomic.StoreInt32(&passed, 0)
	} else if ptr.F1 == 0 {
		println("Zero data value encountered in the packet")
		atomic.StoreInt32(&passed, 0)
	}
	if newValue >= totalPackets {
		testDoneEvent.Signal()
	}
}

func fixPacket(pkt *packet.Packet, context flow.UserContext) {
	if stabilityCommon.ShouldBeSkipped(pkt) {
		return
	}
	fixMACAddrs1(pkt, context)

	res := pkt.ParseData()
	if res < 0 {
		println("ParseL4 returned negative value", res)
		println("TEST FAILED")
		return
	}

	ptr := (*testResendCommon.Packetdata)(pkt.Data)
	if ptr.F2 != 0 {
		fmt.Printf("Bad data found in the packet: %x\n", ptr.F2)
		println("TEST FAILED")
		return
	}

	ptr.F2 = ptr.F1
}
