// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
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
	"github.com/intel-go/yanff/test/stability/test1/common"
)

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

	fixMACAddrs func(*packet.Packet, flow.UserContext)
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

// This part of test generates packets on port 0 and receives them on
// port 1. The test records packet's index inside of the first field
// of the packet and sets the second field to zero. It expects the
// other half of the test to copy index from first part of the packet
// to the second part. When packet is received, test routine compares
// first and second halves and checks that they are equal. Test also
// calculates sent/received ratio and prints it when a predefined
// number of packets is received.
func main() {
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport, "inport", 1, "port for receiver")
	flag.Uint64Var(&speed, "speed", speed, "speed of generator")
	flag.Uint64Var(&totalPackets, "number", totalPackets, "total number of packets to receive by test")
	flag.DurationVar(&T, "timeout", T, "test start timeout, time to stabilize speed. Packets sent during timeout do not affect test result")
	configFile := flag.String("config", "", "Specify json config file name (mandatory for VM)")
	target := flag.String("target", "", "Target host name from config file (mandatory for VM)")
	flag.Parse()

	// Init YANFF system at 16 available cores
	config := flow.Config{
		CPUList: "0-15",
	}

	CheckFatal(flow.SystemInit(&config))

	stabilityCommon.InitCommonState(*configFile, *target)
	fixMACAddrs = stabilityCommon.ModifyPacket[outport].(func(*packet.Packet, flow.UserContext))

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	firstFlow, err := flow.SetFastGenerator(generatePacket, speed, nil)
	CheckFatal(err)

	// Send all generated packets to the output
	CheckFatal(flow.SetSender(firstFlow, uint8(outport)))

	// Create receiving flow and set a checking function for it
	secondFlow, err := flow.SetReceiver(uint8(inport))
	CheckFatal(err)
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
	ptr := (*common.Packetdata)(emptyPacket.Data)

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
	ptr := (*common.Packetdata)(pkt.Data)
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
