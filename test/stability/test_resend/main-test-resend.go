// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"

	"github.com/intel-go/yanff/test/stability/stabilityCommon"
	"github.com/intel-go/yanff/test/stability/test_resend/testResendCommon"
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

	cores uint

	fixMACAddrs  func(*packet.Packet, flow.UserContext)
	fixMACAddrs1 func(*packet.Packet, flow.UserContext)
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

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
	flag.Parse()
	executeTest(*configFile, *target, testScenario)
}

func executeTest(configFile, target string, testScenario uint) {
	if testScenario > 3 || testScenario < 0 {
		CheckFatal(errors.New("testScenario should be in interval [0, 3]"))
	}
	// Init YANFF system
	config := flow.Config{}

	CheckFatal(flow.SystemInit(&config))

	stabilityCommon.InitCommonState(configFile, target)
	fixMACAddrs = stabilityCommon.ModifyPacket[outport].(func(*packet.Packet, flow.UserContext))
	fixMACAddrs1 = stabilityCommon.ModifyPacket[outport].(func(*packet.Packet, flow.UserContext))

	if testScenario == 2 {
		inputFlow, err := flow.SetReceiver(uint8(inport))
		CheckFatal(err)
		CheckFatal(flow.SetHandler(inputFlow, fixPacket, nil))
		CheckFatal(flow.SetSender(inputFlow, uint8(outport)))

		// Begin to process packets.
		CheckFatal(flow.SystemStart())
	} else {
		var m sync.Mutex
		testDoneEvent = sync.NewCond(&m)

		firstFlow, err := flow.SetFastGenerator(generatePacket, speed, nil)
		CheckFatal(err)
		var secondFlow *flow.Flow
		if testScenario == 1 {
			// Send all generated packets to the output
			CheckFatal(flow.SetSender(firstFlow, uint8(outport)))
			// Create receiving flow and set a checking function for it
			secondFlow, err = flow.SetReceiver(uint8(inport))
			CheckFatal(err)
		} else {
			secondFlow = firstFlow
			CheckFatal(flow.SetHandler(secondFlow, fixPacket, nil))
		}
		CheckFatal(flow.SetHandler(secondFlow, checkPackets, nil))
		CheckFatal(flow.SetStopper(secondFlow))

		// Start pipeline
		go func() {
			CheckFatal(flow.SystemStart())
		}()
		progStart = time.Now()

		// Wait for enough packets to arrive
		testDoneEvent.L.Lock()
		testDoneEvent.Wait()
		testDoneEvent.L.Unlock()
		composeStatistics()
	}
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
