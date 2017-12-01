// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"github.com/intel-go/yanff/test/localTesting/pktgen/parseConfig"
)

var (
	count uint64

	testDoneEvent *sync.Cond
	configuration *parseConfig.PacketConfig

	outFile      string
	inFile       string
	totalPackets uint64
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	flag.StringVar(&outFile, "outfile", "pkts_generated.pcap", "file to write output to")
	flag.StringVar(&inFile, "infile", "config.json", "file with configurations for generator")
	flag.Uint64Var(&totalPackets, "totalPackets", 10000000, "stop after generation totalPackets number")
	flag.Parse()

	var err error
	configuration, err = ReadConfig(inFile)
	if err != nil {
		panic(fmt.Sprintf("config reading failed: %v", err))
	}

	// Init YANFF system at 16 available cores
	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	generator, err := getGenerator()
	CheckFatal(err)
	// Create packet flow
	outputFlow, err := flow.SetGenerator(generator, 0, nil)
	CheckFatal(err)
	CheckFatal(flow.SetWriter(outputFlow, outFile))
	// Start pipeline
	go func() {
		CheckFatal(flow.SystemStart())
	}()

	// Wait for enough packets to arrive
	testDoneEvent.L.Lock()
	testDoneEvent.Wait()
	testDoneEvent.L.Unlock()

	sent := atomic.LoadUint64(&count)

	// Print report
	println("Sent", sent, "packets")
}

// ReadConfig function reads and parses config file.
func ReadConfig(fileName string) (*parseConfig.PacketConfig, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("opening file failed with: %v ", err)
	}
	cfg, err := parseConfig.ParsePacketConfig(f)
	if err != nil {
		return nil, fmt.Errorf("parsing config failed with: %v", err)
	}
	return cfg, nil
}

func getNextAddr(addr parseConfig.AddrRange) (nextAddr []uint8) {
	if addr.Incr == 0 {
		return addr.Start
	}
	if len(addr.Start) == 0 {
		return []uint8{0}
	}
	if bytes.Compare(addr.Start, addr.Min) > 0 || bytes.Compare(addr.Start, addr.Max) < 0 {
		addr.Start = addr.Min
	}
	nextAddr = addr.Start
	addressInt := big.NewInt(0)
	addressInt.SetBytes(addr.Start)
	addressInt.Add(big.NewInt(int64(addr.Incr)), addressInt)
	newAddr := addressInt.Bytes()
	if len(newAddr) >= len(addr.Start) {
		copy(addr.Start[:], newAddr[len(newAddr)-len(addr.Start):])
	} else {
		copy(addr.Start[len(addr.Start)-len(newAddr):], newAddr[:])
	}
	if bytes.Compare(addr.Start, addr.Max) <= 0 {
		addr.Start = addr.Min
	}
	return nextAddr
}

func copyAddr(destination []uint8, source []uint8, size int) {
	if size < len(source) {
		copy(destination[:], source[len(source)-size:])
	} else {
		copy(destination[size-len(source):], source[:])
	}
}

func cropAddr(addr []uint8, size int) []uint8 {
	cropped := make([]uint8, size)
	if size < len(addr) {
		copy(cropped[:], addr[len(addr)-size:])
	} else {
		copy(cropped[size-len(addr):], addr[:])
	}
	return cropped
}

func getNextPort(port parseConfig.PortRange) (nextPort uint16) {
	if len(port.Start) == 0 {
		return 0
	}
	if port.Start[0] < port.Min || port.Start[0] > port.Max {
		port.Start[0] = port.Min
	}
	nextPort = port.Start[0]
	port.Start[0] += port.Incr
	return nextPort
}

func getNextSeqNumber(seq parseConfig.Sequence) (nextSeqNum uint32) {
	if len(seq.Next) == 0 {
		return 0
	}
	nextSeqNum = seq.Next[0]
	if seq.Type == parseConfig.RANDOM {
		seq.Next[0] = rand.Uint32()
	} else if seq.Type == parseConfig.INCREASING {
		seq.Next[0]++
	}
	return nextSeqNum
}

func generateData(configuration interface{}) ([]uint8, error) {
	switch data := configuration.(type) {
	case parseConfig.Raw:
		pktData := make([]uint8, len(data.Data))
		copy(pktData[:], ([]uint8(data.Data)))
		return pktData, nil
	case parseConfig.RandBytes:
		maxZise := data.Size + data.Deviation
		minSize := data.Size - data.Deviation
		randSize := uint(rand.Float64()*float64(maxZise-minSize) + float64(minSize))
		pktData := make([]uint8, randSize)
		for i := range pktData {
			pktData[i] = byte(rand.Int())
		}
		return pktData, nil
	case []parseConfig.PDistEntry:
		prob := 0.0
		rndN := math.Abs(rand.Float64())
		maxProb := parseConfig.PDistEntry{Probability: 0}
		for _, item := range data {
			prob += item.Probability
			if rndN <= prob {
				pktData, err := generateData(item.Data)
				if err != nil {
					return nil, fmt.Errorf("failed to fill data with pdist data type: %v", err)
				}
				return pktData, nil
			}
			if item.Probability > maxProb.Probability {
				maxProb = item
			}
		}
		if prob <= 0 || prob > 1 {
			return nil, fmt.Errorf("sum of pdist probabilities is invalid, %f", prob)
		}
		// get the variant with max prob
		// if something went wrong and rand did not match any prob
		// may happen if sum of prob was not 1
		pktData, err := generateData(maxProb.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to fill data with pdist data type: %v", err)
		}
		return pktData, nil
	}
	return nil, fmt.Errorf("unknown data type")
}

func getGenerator() (interface{}, error) {
	switch l2 := (configuration.Data).(type) {
	case parseConfig.EtherConfig:
		switch l3 := l2.Data.(type) {
		case parseConfig.IPConfig:
			switch l3.Data.(type) {
			case parseConfig.TCPConfig:
				return generateTCPIP, nil
			case parseConfig.UDPConfig:
				return generateUDPIP, nil
			case parseConfig.ICMPConfig:
				return generateICMPIP, nil
			case parseConfig.Raw, parseConfig.RandBytes, []parseConfig.PDistEntry:
				return generateIP, nil
			default:
				return nil, fmt.Errorf("unknown packet l4 configuration")
			}
		case parseConfig.ARPConfig:
			return generateARP, nil
		case parseConfig.Raw, parseConfig.RandBytes, []parseConfig.PDistEntry:
			return generateEther, nil
		default:
			return nil, fmt.Errorf("unknown packet l3 configuration")
		}
	default:
		return nil, fmt.Errorf("unknown packet l2 configuration")
	}
}

func checkFinish() {
	if count >= totalPackets {
		time.Sleep(time.Second)
		testDoneEvent.Signal()
	}
}

func generateEther(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	atomic.AddUint64(&count, 1)
	l2 := configuration.Data.(parseConfig.EtherConfig)
	data, err := generateData(l2.Data)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse data for l2: %v", err))
	}
	if data == nil {
		panic(fmt.Sprintf("failed to generate data"))
	}
	size := uint(len(data))
	if !packet.InitEmptyPacket(pkt, size) {
		panic(fmt.Sprintf("InitEmptyPacket failed"))
	}
	copy((*[1 << 30]uint8)(pkt.Data)[0:size], data)
	if err := fillEtherHdr(pkt, l2); err != nil {
		panic(fmt.Sprintf("failed to fill ether header %v", err))
	}
}

func generateIP(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	atomic.AddUint64(&count, 1)
	l2 := configuration.Data.(parseConfig.EtherConfig)
	l3 := l2.Data.(parseConfig.IPConfig)
	data, err := generateData(l3.Data)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse data for l3: %v", err))
	}
	if data == nil {
		panic(fmt.Sprintf("failed to generate data"))
	}
	size := uint(len(data))
	if l3.Version == 4 {
		if !packet.InitEmptyIPv4Packet(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv4Packet returned false"))
		}
	} else if l3.Version == 6 {
		if !packet.InitEmptyIPv6Packet(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv6Packet returned false"))
		}
	} else {
		panic(fmt.Sprintf("fillPacketl3 failed, unknovn version %d", l3.Version))
	}
	copy((*[1 << 30]uint8)(pkt.Data)[0:size], data)

	if err := fillIPHdr(pkt, l3); err != nil {
		panic(fmt.Sprintf("failed to fill ip header %v", err))
	}
	if err := fillEtherHdr(pkt, l2); err != nil {
		panic(fmt.Sprintf("failed to fill ether header %v", err))
	}
	if l3.Version == 4 {
		pkt.GetIPv4().HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4()))
	}
}

func generateARP(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	atomic.AddUint64(&count, 1)
	l2 := configuration.Data.(parseConfig.EtherConfig)
	l3 := l2.Data.(parseConfig.ARPConfig)
	var SHA, THA [common.EtherAddrLen]uint8
	copyAddr(SHA[:], getNextAddr(l3.SHA), common.EtherAddrLen)
	SPA := binary.LittleEndian.Uint32(net.IP(getNextAddr(l3.SPA)).To4())

	switch l3.Operation {
	case packet.ARPRequest:
		if l3.Gratuitous {
			if !packet.InitGARPAnnouncementRequestPacket(pkt, SHA, SPA) {
				panic(fmt.Sprintf("InitGARPAnnouncementRequestPacket returned false"))
			}
		} else {
			TPA := binary.LittleEndian.Uint32(net.IP(getNextAddr(l3.TPA)).To4())
			if !packet.InitARPRequestPacket(pkt, SHA, SPA, TPA) {
				panic(fmt.Sprintf("InitARPRequestPacket returned false"))
			}
		}
	case packet.ARPReply:
		if l3.Gratuitous {
			if !packet.InitGARPAnnouncementReplyPacket(pkt, SHA, SPA) {
				panic(fmt.Sprintf("InitGARPAnnouncementReplyPacket returned false"))
			}
		} else {
			copyAddr(THA[:], getNextAddr(l3.THA), common.EtherAddrLen)
			TPA := binary.LittleEndian.Uint32(net.IP(getNextAddr(l3.TPA)).To4())
			if !packet.InitARPReplyPacket(pkt, SHA, THA, SPA, TPA) {
				panic(fmt.Sprintf("InitARPReplyPacket returned false"))
			}
		}
	default:
		panic(fmt.Sprintf("unsupported operation code: %d", l3.Operation))
	}
	if len(l2.DAddr.Start) != 0 {
		copyAddr(pkt.Ether.DAddr[:], getNextAddr(l2.DAddr), common.EtherAddrLen)
	}
	if l2.VLAN != nil {
		if !pkt.AddVLANTag(l2.VLAN.TCI) {
			panic("failed to add vlan tag to arp packet")
		}
	}
}

func generateTCPIP(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	atomic.AddUint64(&count, 1)
	l2 := configuration.Data.(parseConfig.EtherConfig)
	l3 := l2.Data.(parseConfig.IPConfig)
	l4 := l3.Data.(parseConfig.TCPConfig)
	data, err := generateData(l4.Data)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse data for l4: %v", err))
	}
	if data == nil {
		panic(fmt.Sprintf("failed to generate data"))
	}
	size := uint(len(data))
	if l3.Version == 4 {
		if !packet.InitEmptyIPv4TCPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv4TCPPacket returned false"))
		}
	} else if l3.Version == 6 {
		if !packet.InitEmptyIPv6TCPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv6TCPPacket returned false"))
		}
	} else {
		panic(fmt.Sprintf("fill packet l4 failed, unknovn version %d", l3.Version))
	}
	copy((*[1 << 30]uint8)(pkt.Data)[0:size], data)

	if err := fillTCPHdr(pkt, l4); err != nil {
		panic(fmt.Sprintf("failed to fill tcp header %v", err))
	}
	if err := fillIPHdr(pkt, l3); err != nil {
		panic(fmt.Sprintf("failed to fill ip header %v", err))
	}
	if err := fillEtherHdr(pkt, l2); err != nil {
		panic(fmt.Sprintf("failed to fill ether header %v", err))
	}
	if l3.Version == 4 {
		pkt.GetIPv4().HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4()))
		pkt.GetTCPForIPv4().Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(pkt.GetIPv4(), pkt.GetTCPForIPv4(), pkt.Data))
	} else if l3.Version == 6 {
		pkt.GetTCPForIPv6().Cksum = packet.SwapBytesUint16(packet.CalculateIPv6TCPChecksum(pkt.GetIPv6(), pkt.GetTCPForIPv6(), pkt.Data))
	}
}

func generateUDPIP(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	atomic.AddUint64(&count, 1)
	l2 := configuration.Data.(parseConfig.EtherConfig)
	l3 := l2.Data.(parseConfig.IPConfig)
	l4 := l3.Data.(parseConfig.UDPConfig)
	data, err := generateData(l4.Data)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse data for l4: %v", err))
	}
	if data == nil {
		panic(fmt.Sprintf("failed to generate data"))
	}
	size := uint(len(data))
	if l3.Version == 4 {
		if !packet.InitEmptyIPv4UDPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv4UDPPacket returned false"))
		}
	} else if l3.Version == 6 {
		if !packet.InitEmptyIPv6UDPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv6UDPPacket returned false"))
		}
	} else {
		panic(fmt.Sprintf("fill packet l4 failed, unknovn version %d", l3.Version))
	}
	copy((*[1 << 30]uint8)(pkt.Data)[0:size], data)

	if err := fillUDPHdr(pkt, l4); err != nil {
		panic(fmt.Sprintf("failed to fill udp header %v", err))
	}
	if err := fillIPHdr(pkt, l3); err != nil {
		panic(fmt.Sprintf("failed to fill ip header %v", err))
	}
	if err := fillEtherHdr(pkt, l2); err != nil {
		panic(fmt.Sprintf("failed to fill ether header %v", err))
	}
	if l3.Version == 4 {
		pkt.GetIPv4().HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4()))
		pkt.GetUDPForIPv4().DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pkt.GetIPv4(), pkt.GetUDPForIPv4(), pkt.Data))
	} else if l3.Version == 6 {
		pkt.GetUDPForIPv6().DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv6UDPChecksum(pkt.GetIPv6(), pkt.GetUDPForIPv6(), pkt.Data))
	}
}

func generateICMPIP(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	atomic.AddUint64(&count, 1)
	l2 := configuration.Data.(parseConfig.EtherConfig)
	l3 := l2.Data.(parseConfig.IPConfig)
	l4 := l3.Data.(parseConfig.ICMPConfig)
	data, err := generateData(l4.Data)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse data for l4: %v", err))
	}
	if data == nil {
		panic(fmt.Sprintf("failed to generate data"))
	}
	size := uint(len(data))
	if l3.Version == 4 {
		if !packet.InitEmptyIPv4ICMPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv4ICMPPacket returned false"))
		}
	} else if l3.Version == 6 {
		if !packet.InitEmptyIPv6ICMPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv6ICMPPacket returned false"))
		}
	} else {
		panic(fmt.Sprintf("fill packet l4 failed, unknovn version %d", l3.Version))
	}
	copy((*[1 << 30]uint8)(pkt.Data)[0:size], data)

	if err := fillICMPHdr(pkt, l4); err != nil {
		panic(fmt.Sprintf("failed to fill icmp header %v", err))
	}
	if err := fillIPHdr(pkt, l3); err != nil {
		panic(fmt.Sprintf("failed to fill ip header %v", err))
	}
	if err := fillEtherHdr(pkt, l2); err != nil {
		panic(fmt.Sprintf("failed to fill ether header %v", err))
	}
	if l3.Version == 4 {
		pkt.GetIPv4().HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4()))
		pkt.GetICMPForIPv4().Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(pkt.GetIPv4(), pkt.GetICMPForIPv4(), pkt.Data))
	} else if l3.Version == 6 {
		pkt.GetICMPForIPv6().Cksum = packet.SwapBytesUint16(packet.CalculateIPv6ICMPChecksum(pkt.GetIPv6(), pkt.GetICMPForIPv6(), pkt.Data))
	}
}

func fillTCPHdr(pkt *packet.Packet, l4 parseConfig.TCPConfig) error {
	emptyPacketTCP := (*packet.TCPHdr)(pkt.L4)
	emptyPacketTCP.SrcPort = packet.SwapBytesUint16(getNextPort(l4.SPort))
	emptyPacketTCP.DstPort = packet.SwapBytesUint16(getNextPort(l4.DPort))
	emptyPacketTCP.SentSeq = packet.SwapBytesUint32(getNextSeqNumber(l4.Seq))
	emptyPacketTCP.TCPFlags = l4.Flags
	return nil
}

func fillUDPHdr(pkt *packet.Packet, l4 parseConfig.UDPConfig) error {
	emptyPacketUDP := (*packet.UDPHdr)(pkt.L4)
	emptyPacketUDP.SrcPort = packet.SwapBytesUint16(getNextPort(l4.SPort))
	emptyPacketUDP.DstPort = packet.SwapBytesUint16(getNextPort(l4.DPort))
	return nil
}

func fillICMPHdr(pkt *packet.Packet, l4 parseConfig.ICMPConfig) error {
	emptyPacketICMP := (*packet.ICMPHdr)(pkt.L4)
	emptyPacketICMP.Type = l4.Type
	emptyPacketICMP.Code = l4.Code
	emptyPacketICMP.Identifier = l4.Identifier
	emptyPacketICMP.SeqNum = packet.SwapBytesUint16(uint16(getNextSeqNumber(l4.Seq)))
	return nil
}

func fillIPHdr(pkt *packet.Packet, l3 parseConfig.IPConfig) error {
	if l3.Version == 4 {
		pktIP := pkt.GetIPv4()
		pktIP.SrcAddr = binary.LittleEndian.Uint32(net.IP(getNextAddr(l3.SAddr)).To4())
		pktIP.DstAddr = binary.LittleEndian.Uint32(net.IP(getNextAddr(l3.DAddr)).To4())
		return nil
	}
	pktIP := pkt.GetIPv6()
	nextAddr := getNextAddr(l3.SAddr)
	copyAddr(pktIP.SrcAddr[:], nextAddr, common.IPv6AddrLen)
	nextAddr = getNextAddr(l3.DAddr)
	copyAddr(pktIP.DstAddr[:], nextAddr, common.IPv6AddrLen)
	return nil
}

func fillEtherHdr(pkt *packet.Packet, l2 parseConfig.EtherConfig) error {
	if l2.VLAN != nil {
		if err := addVLAN(pkt, l2.VLAN.TCI); err != nil {
			return err
		}
	}
	nextAddr := getNextAddr(l2.DAddr)
	copyAddr(pkt.Ether.DAddr[:], nextAddr, common.EtherAddrLen)
	nextAddr = getNextAddr(l2.SAddr)
	copyAddr(pkt.Ether.SAddr[:], nextAddr, common.EtherAddrLen)
	return nil
}

// faster version of packet.AddVLANTag, can be used only
// when ether src and dst are not set, but ether type is
// (most InitEmptyPacket functions do so).
func addVLAN(pkt *packet.Packet, tag uint16) error {
	if !pkt.EncapsulateHead(0, 4) {
		return fmt.Errorf("failed to add vlan tag, EncapsulateHead returned false")
	}
	pkt.Ether.EtherType = packet.SwapBytesUint16(common.VLANNumber)
	vhdr := pkt.GetVLAN()
	if vhdr == nil {
		return fmt.Errorf("failed to get vlan, GetVLAN returned nil")
	}
	vhdr.TCI = packet.SwapBytesUint16(tag)
	return nil
}
