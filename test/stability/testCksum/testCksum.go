// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"

	"github.com/intel-go/nff-go/test/stability/stabilityCommon"
	"github.com/intel-go/nff-go/test/stability/testCksum/testCksumCommon"
)

// Test with flag testScenario=1:
// generates packets on outport and receives
// them on inport. The test records packet's index inside of the first field
// of the packet and sets the second field to zero. It expects the
// other half of the test to copy index from first part of the packet
// to the second part. When packet is received, test routine compares
// first and second halves and checks that they are equal. Test also
// calculates sent/received ratio and prints it when a predefined
// number of packets is received.
//
// Test with flag testScenario=2:
// receives packets at inport,
// copies index from first part of the packet to the second part
// and sends to outport.
//
// Test with testScenario=0:
// makes all it in one pipeline without actual send and receive.

var (
	totalPackets uint64 = 10

	// Packet should hold at least two int64 fields
	minPayloadSize = int(unsafe.Sizeof(sentPackets) * 2)
	maxPayloadSize = 1400

	sentPackets     uint64
	receivedPackets uint64
	testDoneEvent   *sync.Cond
	passed          int32 = 1
	rnd             *rand.Rand

	hwol         bool
	inport       uint
	outport      uint
	useIPv4      bool
	useIPv6      bool
	randomL3     = false
	useUDP       bool
	useTCP       bool
	useICMP      bool
	useVLAN      bool
	randomL4     = false
	packetLength int
	ipVersion    uint   = 4
	tci          uint16 = 2
	dpdkLogLevel        = "--log-level=0"
	protocol            = stabilityCommon.TypeUdp
)

func main() {
	var testScenario uint
	flag.UintVar(&testScenario, "testScenario", 0, "1 to use 1st part scenario, 2 snd, 0 to use one-machine test")
	flag.BoolVar(&hwol, "hwol", false, "Use Hardware offloading for TX checksums calculation")
	flag.UintVar(&inport, "inport", 1, "Input port number")
	flag.UintVar(&outport, "outport", 0, "Output port number")
	flag.BoolVar(&useUDP, "udp", false, "Generate UDP packets")
	flag.BoolVar(&useTCP, "tcp", false, "Generate TCP packets")
	flag.BoolVar(&useICMP, "icmp", false, "Generate ICMP Echo Request packets")
	flag.BoolVar(&useIPv4, "ipv4", false, "Generate IPv4 packets")
	flag.BoolVar(&useIPv6, "ipv6", false, "Generate IPv6 packets")
	flag.BoolVar(&useVLAN, "vlan", false, "Add VLAN tag to all packets")
	flag.IntVar(&packetLength, "size", 0, "Specify length of packets to be generated")
	flag.Uint64Var(&totalPackets, "number", totalPackets, "Number of packets to send")
	dpdkLogLevel = *(flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL"))
	flag.Parse()

	if useIPv4 {
		if useIPv6 {
			print("IPv4 and IPv6 L3 and ")
			randomL3 = true
		} else {
			print("IPv4 L3 and ")
		}
	} else {
		if useIPv6 {
			print("IPv6 L3 and ")
			ipVersion = 6
		} else {
			println("No L3 IP mode selected. Enabling IPv4 by default")
		}
	}
	if !useUDP && !useTCP && !useICMP {
		println("No L4 packet type mode selected. Enabling UDP by default")
		useUDP = true
	}

	if useUDP && !useTCP && !useICMP {
		println("UDP L4 mode is enabled")
	} else if !useUDP && useTCP && !useICMP {
		println("TCP L4 mode is enabled")
		protocol = stabilityCommon.TypeTcp
	} else if !useUDP && !useTCP && useICMP {
		println("ICMP L4 mode is enabled")
		protocol = stabilityCommon.TypeIcmp
	} else {
		println("UDP and TCP L4 modes are enabled")
		randomL4 = true
	}

	if useICMP && hwol {
		println("Warning: cannot use HW offloading with ICMP protocol, only for L3 ipv4")
		if useIPv6 {
			println("Can't calculate anything for configuration: ipv6 + icmp + hw mode, exiting")
			os.Exit(1)
		}
	}

	if err := executeTest(testScenario); err != nil {
		fmt.Printf("fail: %+v\n", err)
	}
}

func executeTest(testScenario uint) error {
	if testScenario > 3 || testScenario < 0 {
		return errors.New("testScenario should be in interval [0, 3]")
	}
	rnd = rand.New(rand.NewSource(13))
	// Init NFF-GO system at 16 available cores
	config := flow.Config{
		HWTXChecksum: hwol,
		DPDKArgs:     []string{dpdkLogLevel},
	}
	if err := flow.SystemInit(&config); err != nil {
		return err
	}

	if testScenario == 2 {
		// Receive packets from zero port. Receive queue will be added automatically.
		inputFlow, err := flow.SetReceiver(uint8(inport))
		if err != nil {
			return err
		}
		if err := flow.SetHandlerDrop(inputFlow, filterPacketsUdpTcpIcmp, nil); err != nil {
			return err
		}
		if err := flow.SetHandler(inputFlow, checkChecksum, nil); err != nil {
			return err
		}
		if err := flow.SetHandler(inputFlow, fixPacket, nil); err != nil {
			return err
		}
		if err := flow.SetSender(inputFlow, uint8(outport)); err != nil {
			return err
		}

		// Begin to process packets.
		if err := flow.SystemStart(); err != nil {
			return err
		}
	} else {
		var m sync.Mutex
		testDoneEvent = sync.NewCond(&m)

		// Use here usual generator (enabled if speed = 0).
		// High performance generator (enabled if speed != 0) is not used here, as it
		// can send fully only number of packets N which is multiple of burst size (default 32),
		// otherwise last N%burstSize packets are not sent, and cannot send N less than burstSize.
		generatedFlow := flow.SetGenerator(generatePacket, nil)
		var finalFlow *flow.Flow
		var err error
		if testScenario == 1 {
			// Send all generated packets to the output
			if err := flow.SetSender(generatedFlow, uint8(outport)); err != nil {
				return err
			}
			// Create receiving flow and set a checking function for it
			finalFlow, err = flow.SetReceiver(uint8(inport))
			if err != nil {
				return err
			}
		} else {
			finalFlow = generatedFlow
			if err := flow.SetHandler(finalFlow, fixPacket, nil); err != nil {
				return err
			}
		}
		if err := flow.SetHandlerDrop(finalFlow, filterPackets, nil); err != nil {
			return err
		}
		if err := flow.SetHandler(finalFlow, checkPackets, nil); err != nil {
			return err
		}
		if err := flow.SetStopper(finalFlow); err != nil {
			return err
		}

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

		return composeStatistics()
	}
	return nil
}

func filterPackets(pkt *packet.Packet, context flow.UserContext) bool {
	l3 := ipVersion
	l4 := protocol
	if randomL3 {
		l3 = 0
	}
	if randomL4 {
		l4 = stabilityCommon.TypeUdpTcp
	}
	if stabilityCommon.ShouldBeSkippedAllExcept(pkt, l3, l4) {
		return false
	}
	return true
}

func filterPacketsUdpTcpIcmp(pkt *packet.Packet, context flow.UserContext) bool {
	return !stabilityCommon.ShouldBeSkippedAllExcept(pkt, 0, stabilityCommon.TypeUdpTcpIcmp)
}

func fixPacket(pkt *packet.Packet, context flow.UserContext) {
	pkt.ParseDataCheckVLAN()
	ptr := (*testCksumCommon.Packetdata)(pkt.Data)
	if ptr.F2 != 0 {
		fmt.Printf("Bad data found in the packet: %x\n", ptr.F2)
		println("TEST FAILED")
		return
	}

	ptr.F2 = ptr.F1

	if hwol {
		packet.SetHWOffloadingHdrChecksum(pkt)
		pkt.SetHWCksumOLFlags()
	} else {
		testCksumCommon.CalculateChecksum(pkt)
	}
}

func checkChecksum(pkt *packet.Packet, context flow.UserContext) {
	offset := pkt.ParseDataCheckVLAN()
	if offset < 0 {
		println("ParseDataCheckVLAN returned negative value", offset)
		println("TEST FAILED")
		return
	}
	if !testCksumCommon.CheckPacketChecksums(pkt) {
		println("TEST FAILED")
		atomic.StoreInt32(&passed, 0)
	}
}

func composeStatistics() error {
	// Compose statistics
	sent := atomic.LoadUint64(&sentPackets)
	received := atomic.LoadUint64(&receivedPackets)
	ratio := received * 100 / sent

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")
	println("Ratio = ", ratio, "%")
	if atomic.LoadInt32(&passed) != 0 && ratio >= 90 {
		println("TEST PASSED")
		return nil
	}
	println("TEST FAILED")
	return errors.New("final statistics check failed")
}

func generatePayloadLength() uint16 {
	if packetLength == 0 {
		return uint16(rnd.Intn(maxPayloadSize-minPayloadSize) + minPayloadSize)
	}
	return uint16(packetLength)
}

func generatePacket(emptyPacket *packet.Packet, context flow.UserContext) {
	if randomL3 {
		if rnd.Int()%2 == 0 {
			ipVersion = 6
		} else {
			ipVersion = 4
		}
	}
	if randomL4 {
		if rnd.Int()%2 == 0 {
			protocol = stabilityCommon.TypeTcp
		} else {
			protocol = stabilityCommon.TypeUdp
		}
	}

	if ipVersion == 4 {
		if protocol == stabilityCommon.TypeUdp {
			generateIPv4UDP(emptyPacket)
		} else if protocol == stabilityCommon.TypeIcmp {
			generateIPv4ICMP(emptyPacket)
		} else {
			generateIPv4TCP(emptyPacket)
		}
	} else {
		if protocol == stabilityCommon.TypeUdp {
			generateIPv6UDP(emptyPacket)
		} else if protocol == stabilityCommon.TypeIcmp {
			generateIPv6ICMP(emptyPacket)
		} else {
			generateIPv6TCP(emptyPacket)
		}
	}

	if useVLAN {
		emptyPacket.AddVLANTag(tci)
		if hwol {
			// l2 len changed after add VLAN tag, need to reset hwol flags
			emptyPacket.SetHWCksumOLFlags()
		}
	}

	atomic.AddUint64(&sentPackets, 1)
}

func initPacketCommon(emptyPacket *packet.Packet, length uint16) {
	// Initialize ethernet addresses
	emptyPacket.Ether.DAddr = [6]uint8{0xde, 0xea, 0xad, 0xbe, 0xee, 0xef}
	emptyPacket.Ether.SAddr = [6]uint8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

	// Fill internals with random garbage
	data := (*[1 << 30]byte)(emptyPacket.Data)[0:length]
	for i := range data {
		data[i] = byte(rnd.Int())
	}

	// Put a unique non-zero value here
	sent := atomic.LoadUint64(&sentPackets)
	ptr := (*testCksumCommon.Packetdata)(emptyPacket.Data)
	ptr.F1 = sent + 1
	ptr.F2 = 0
}

func initPacketIPv4(emptyPacket *packet.Packet) {
	// Initialize IPv4 addresses
	emptyPacketIPv4 := emptyPacket.GetIPv4()
	emptyPacketIPv4.SrcAddr = packet.SwapBytesUint32((192 << 24) | (168 << 16) | (1 << 8) | 1)
	emptyPacketIPv4.DstAddr = packet.SwapBytesUint32((192 << 24) | (168 << 16) | (1 << 8) | 2)
	emptyPacketIPv4.TimeToLive = 100
}

func initPacketIPv6(emptyPacket *packet.Packet) {
	// Initialize IPv6 addresses
	emptyPacketIPv6 := emptyPacket.GetIPv6()
	emptyPacketIPv6.SrcAddr = [common.IPv6AddrLen]uint8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	emptyPacketIPv6.DstAddr = [common.IPv6AddrLen]uint8{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
}

func initPacketUDP(emptyPacket *packet.Packet) {
	emptyPacketUDP := (*packet.UDPHdr)(emptyPacket.L4)
	emptyPacketUDP.SrcPort = packet.SwapBytesUint16(1234)
	emptyPacketUDP.DstPort = packet.SwapBytesUint16(2345)
}

func initPacketTCP(emptyPacket *packet.Packet) {
	emptyPacketTCP := (*packet.TCPHdr)(emptyPacket.L4)
	emptyPacketTCP.SrcPort = packet.SwapBytesUint16(3456)
	emptyPacketTCP.DstPort = packet.SwapBytesUint16(4567)
}

func initPacketICMP(emptyPacket *packet.Packet) {
	emptyPacketICMP := (*packet.ICMPHdr)(emptyPacket.L4)
	emptyPacketICMP.Type = common.ICMPTypeEchoRequest
	emptyPacketICMP.Identifier = 0xdead
	emptyPacketICMP.SeqNum = 0xbeef
}

func generateIPv4UDP(emptyPacket *packet.Packet) {
	length := generatePayloadLength()
	packet.InitEmptyIPv4UDPPacket(emptyPacket, uint(length))

	initPacketCommon(emptyPacket, length)
	initPacketIPv4(emptyPacket)
	initPacketUDP(emptyPacket)

	pIPv4 := emptyPacket.GetIPv4()
	pUDP := emptyPacket.GetUDPForIPv4()
	if hwol {
		pUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv4UDPCksum(pIPv4, pUDP))
	} else {
		pIPv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pIPv4))
		pUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pIPv4, pUDP, emptyPacket.Data))
	}
}

func generateIPv4TCP(emptyPacket *packet.Packet) {
	length := generatePayloadLength()
	packet.InitEmptyIPv4TCPPacket(emptyPacket, uint(length))

	initPacketCommon(emptyPacket, length)
	initPacketIPv4(emptyPacket)
	initPacketTCP(emptyPacket)

	pIPv4 := emptyPacket.GetIPv4()
	pTCP := emptyPacket.GetTCPForIPv4()
	if hwol {
		pTCP.Cksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv4TCPCksum(pIPv4))
	} else {
		pIPv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pIPv4))
		pTCP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(pIPv4, pTCP, emptyPacket.Data))
	}
}

func generateIPv4ICMP(emptyPacket *packet.Packet) {
	length := generatePayloadLength()
	packet.InitEmptyIPv4ICMPPacket(emptyPacket, uint(length))

	initPacketCommon(emptyPacket, length)
	initPacketIPv4(emptyPacket)
	initPacketICMP(emptyPacket)
	pIPv4 := emptyPacket.GetIPv4()
	pICMP := emptyPacket.GetICMPForIPv4()
	if hwol {
		pIPv4.HdrChecksum = 0
		emptyPacket.SetTXIPv4OLFlags(common.EtherLen, common.IPv4MinLen)
	} else {
		pIPv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pIPv4))
	}
	pICMP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(pIPv4, pICMP,
		unsafe.Pointer(uintptr(unsafe.Pointer(pICMP))+common.ICMPLen)))
}

func generateIPv6UDP(emptyPacket *packet.Packet) {
	length := generatePayloadLength()
	packet.InitEmptyIPv6UDPPacket(emptyPacket, uint(length))

	initPacketCommon(emptyPacket, length)
	initPacketIPv6(emptyPacket)
	initPacketUDP(emptyPacket)

	pIPv6 := emptyPacket.GetIPv6()
	pUDP := emptyPacket.GetUDPForIPv6()
	if hwol {
		pUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv6UDPCksum(pIPv6, pUDP))
	} else {
		pUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv6UDPChecksum(pIPv6, pUDP, emptyPacket.Data))
	}
}

func generateIPv6TCP(emptyPacket *packet.Packet) {
	length := generatePayloadLength()
	packet.InitEmptyIPv6TCPPacket(emptyPacket, uint(length))

	initPacketCommon(emptyPacket, length)
	initPacketIPv6(emptyPacket)
	initPacketTCP(emptyPacket)

	pIPv6 := emptyPacket.GetIPv6()
	pTCP := emptyPacket.GetTCPForIPv6()
	if hwol {
		pTCP.Cksum = packet.SwapBytesUint16(packet.CalculatePseudoHdrIPv6TCPCksum(pIPv6))
	} else {
		pTCP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6TCPChecksum(pIPv6, pTCP, emptyPacket.Data))
	}
}

func generateIPv6ICMP(emptyPacket *packet.Packet) {
	length := generatePayloadLength()
	packet.InitEmptyIPv6ICMPPacket(emptyPacket, uint(length))

	initPacketCommon(emptyPacket, length)
	initPacketIPv6(emptyPacket)
	initPacketICMP(emptyPacket)

	if !hwol {
		pIPv6 := emptyPacket.GetIPv6()
		pICMP := emptyPacket.GetICMPForIPv6()
		pICMP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6ICMPChecksum(pIPv6, pICMP, emptyPacket.Data))
	}
}

func checkPackets(pkt *packet.Packet, context flow.UserContext) {
	newValue := atomic.AddUint64(&receivedPackets, 1)
	offset := pkt.ParseDataCheckVLAN()
	if offset < 0 {
		println("ParseL4 returned negative value", offset)
		println("TEST FAILED")
		atomic.StoreInt32(&passed, 0)
	} else {
		if !testCksumCommon.CheckPacketChecksums(pkt) {
			println("TEST FAILED")
			atomic.StoreInt32(&passed, 0)
		}
		ptr := (*testCksumCommon.Packetdata)(pkt.Data)

		if ptr.F1 != ptr.F2 {
			fmt.Printf("Data mismatch in the packet, read %x and %x\n", ptr.F1, ptr.F2)
			println("TEST FAILED")
			atomic.StoreInt32(&passed, 0)
		} else if ptr.F1 == 0 {
			println("Zero data value encountered in the packet")
			println("TEST FAILED")
			atomic.StoreInt32(&passed, 0)
		}
	}

	if newValue >= totalPackets {
		testDoneEvent.Signal()
	}
}
