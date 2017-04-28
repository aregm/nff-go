// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"

	"github.com/intel-go/yanff/test/stability/test1/common"
)

const (
	// With average speed of 1 million packets/s the test runs for
	// about 10 seconds
	TOTAL_PACKETS = 100000000
)

var (
	// Packet should hold two int64 fields
	PACKET_SIZE uint64 = uint64(unsafe.Sizeof(PACKET_SIZE) * 2)

	sentPackets     uint64     = 0
	receivedPackets uint64     = 0
	testDoneEvent   *sync.Cond = nil
	passed          int32      = 1

	outport uint
	inport uint
)

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

	// Init YANFF system at 16 available cores
	flow.SystemInit(16)

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	// Create packets with speed at least 1000 packets/s
	firstFlow := flow.SetGenerator(generatePacket, 1000, nil)
	// Send all generated packets to the output
	flow.SetSender(firstFlow, uint8(outport))

	// Create receiving flow and set a checking function for it
	secondFlow := flow.SetReceiver(uint8(inport))
	flow.SetHandler(secondFlow, checkPackets, nil)
	flow.SetStopper(secondFlow)

	// Start pipeline
	go flow.SystemStart()

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
	packet.InitEmptyEtherIPv4UDPPacket(emptyPacket, uint(PACKET_SIZE))

	emptyPacket.Ether.DAddr = [6]uint8{0xde, 0xad, 0xbe, 0xaf, 0xff, 0xfe}

	sent := atomic.LoadUint64(&sentPackets)
	ptr := (*common.Packetdata)(emptyPacket.Data)
	// Put a unique non-zero value here
	ptr.F1 = sent + 1
	ptr.F2 = 0

	atomic.AddUint64(&sentPackets, 1)
}

func checkPackets(pkt *packet.Packet, context flow.UserContext) {
	newValue := atomic.AddUint64(&receivedPackets, 1)

	offset := pkt.ParseL4Data()
	if offset < 0 {
		println("ParseL4 returned negative value", offset)
		atomic.StoreInt32(&passed, 0)
	} else {
		ptr := (*common.Packetdata)(pkt.Data)

		if ptr.F1 != ptr.F2 {
			fmt.Printf("Data mismatch in the packet, read %x and %x\n", ptr.F1, ptr.F2)
			atomic.StoreInt32(&passed, 0)
		} else if ptr.F1 == 0 {
			println("Zero data value encountered in the packet")
			atomic.StoreInt32(&passed, 0)
		}
	}

	if newValue >= TOTAL_PACKETS {
		testDoneEvent.Signal()
	}
}
