// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package generator

import (
	"fmt"
	"math/rand"
	"os"
	"unsafe"

	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

func getNextValue(addr *AddrRange) {
	if addr.Inc == 0 {
		return
	}
	addr.Current += addr.Inc
	if addr.Current > addr.Max {
		addr.Current = addr.Min
	} else if addr.Current < addr.Min {
		addr.Current = addr.Max
	}
}

func getNextSeqNumber(seq *Sequence, rnd *rand.Rand) {
	if seq.Type == RANDOM {
		seq.Current = rnd.Uint32()
	} else if seq.Type == INCREASING {
		seq.Current++
	}
}

type dataCopier func(unsafe.Pointer, uint, *rand.Rand, unsafe.Pointer)

func copyRaw(configuration unsafe.Pointer, size uint, rnd *rand.Rand, copyTo unsafe.Pointer) {
	data := (*string)(configuration)
	copy((*[1 << 30]uint8)(copyTo)[0:size], ([]uint8(*data)))
}

func copyRand(configuration unsafe.Pointer, size uint, rnd *rand.Rand, copyTo unsafe.Pointer) {
	packetData := (*[1 << 30]uint64)(copyTo)[0 : size/8]
	for i := range packetData {
		packetData[i] = rnd.Uint64()
	}
	tail := (*[1 << 30]byte)(copyTo)[size-size%8 : size]
	for i := range tail {
		tail[i] = byte(rnd.Uint64())
	}
}

func getDataSizeType(configuration *RawBytes, rnd *rand.Rand) (uint, unsafe.Pointer, dataCopier) {
	switch configuration.DType {
	case RAWDATA:
		return uint(len(configuration.Data)), unsafe.Pointer(&configuration.Data), copyRaw
	case RANDDATA:
		data := configuration.Rand
		maxSise := data.Size + data.Deviation
		minSize := data.Size - data.Deviation
		randSize := uint(rnd.Float64()*float64(maxSise-minSize) + float64(minSize))
		return randSize, unsafe.Pointer(uintptr(0)), copyRand
	case PDISTDATA:
		prob := 0.0
		rndN := rnd.Float64()
		for _, item := range configuration.Dist {
			// Sum of all was checked to be 1
			prob += item.Probability
			if rndN <= prob {
				return getDataSizeType1(item.Data, item.Rand, item.DType, rnd)
			}
		}
	}
	panic(fmt.Sprintf("unknown data type"))
}

func getDataSizeType1(Data string, Rand RandBytes, DType DataType, rnd *rand.Rand) (uint, unsafe.Pointer, dataCopier) {
	switch DType {
	case RAWDATA:
		return uint(len(Data)), unsafe.Pointer(&Data), copyRaw
	case RANDDATA:
		maxSise := Rand.Size + Rand.Deviation
		minSize := Rand.Size - Rand.Deviation
		randSize := uint(rnd.Float64()*float64(maxSise-minSize) + float64(minSize))
		return randSize, unsafe.Pointer(uintptr(0)), copyRand
	}
	panic(fmt.Sprintf("unknown data type"))
}

func generateEther(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := &config.Ether
	size, dataConfig, copyDataFunc := getDataSizeType(&l2.Bytes, rnd)

	if !packet.InitEmptyPacket(pkt, size) {
		panic(fmt.Sprintf("InitEmptyPacket failed"))
	}
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	FillEtherHdr(pkt, l2)
}

func generateIPv4(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := &config.Ether
	l3 := &l2.IPv4
	size, dataConfig, copyDataFunc := getDataSizeType(&l3.Bytes, rnd)
	//size, _, _ := getDataSizeType(&l3.Bytes, rnd)
	//size := uint(22)
	if !packet.InitEmptyIPv4Packet(pkt, size) {
		panic(fmt.Sprintf("InitEmptyIPv4Packet returned false"))
	}
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	FillEtherHdr(pkt, l2)
	FillIPv4Hdr(pkt, l3)
	pktIP := (*packet.IPv4Hdr)(pkt.L3)
	pktIP.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pktIP))
}

func generateARP(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := &config.Ether
	l3 := &l2.ARP
	var SHA, THA [types.EtherAddrLen]uint8
	SHA = [types.EtherAddrLen]uint8{byte(l3.SHA.Current >> 40), byte(l3.SHA.Current >> 32), byte(l3.SHA.Current >> 24), byte(l3.SHA.Current >> 16), byte(l3.SHA.Current >> 8), byte(l3.SHA.Current)}
	getNextValue(&l3.SHA)
	SPA := packet.SwapBytesIPv4Addr(types.IPv4Address(l3.SPA.Current))
	getNextValue(&l3.SPA)
	if l3.Operation == packet.ARPRequest {
		if l3.Gratuitous {
			if !packet.InitGARPAnnouncementRequestPacket(pkt, SHA, SPA) {
				panic(fmt.Sprintf("InitGARPAnnouncementRequestPacket returned false"))
			}
		} else {
			TPA := packet.SwapBytesIPv4Addr(types.IPv4Address(l3.TPA.Current))
			getNextValue(&l3.TPA)
			if !packet.InitARPRequestPacket(pkt, SHA, SPA, TPA) {
				panic(fmt.Sprintf("InitARPRequestPacket returned false"))
			}
		}
	} else { //packet.ARPReply
		if l3.Gratuitous {
			if !packet.InitGARPAnnouncementReplyPacket(pkt, SHA, SPA) {
				panic(fmt.Sprintf("InitGARPAnnouncementReplyPacket returned false"))
			}
		} else {
			THA = [types.EtherAddrLen]uint8{byte(l3.THA.Current >> 40), byte(l3.THA.Current >> 32), byte(l3.THA.Current >> 24), byte(l3.THA.Current >> 16), byte(l3.THA.Current >> 8), byte(l3.THA.Current)}
			getNextValue(&l3.THA)
			TPA := packet.SwapBytesIPv4Addr(types.IPv4Address(l3.TPA.Current))
			getNextValue(&l3.TPA)
			if !packet.InitARPReplyPacket(pkt, SHA, THA, SPA, TPA) {
				panic(fmt.Sprintf("InitARPReplyPacket returned false"))
			}
		}
	}
	if l2.VLAN != nil {
		if !pkt.AddVLANTag(l2.VLAN.TCI) {
			panic("failed to add vlan tag to arp packet")
		}
	}
}

func generateTCPIPv4(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := &config.Ether
	l3 := &l2.IPv4
	l4 := &l3.TCP
	size, dataConfig, copyDataFunc := getDataSizeType(&l4.Bytes, rnd)
	if !packet.InitEmptyIPv4TCPPacket(pkt, size) {
		panic(fmt.Sprintf("InitEmptyIPv4TCPPacket returned false"))
	}
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	FillEtherHdr(pkt, l2)
	FillIPv4Hdr(pkt, l3)
	FillTCPHdr(pkt, l4, rnd)
	pktTCP := (*packet.TCPHdr)(pkt.L4)
	pktIP := (*packet.IPv4Hdr)(pkt.L3)
	pktIP.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pktIP))
	pktTCP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(pktIP, pktTCP, pkt.Data))
}

func generateUDPIPv4(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := &config.Ether
	l3 := &l2.IPv4
	l4 := &l3.UDP
	size, dataConfig, copyDataFunc := getDataSizeType(&l4.Bytes, rnd)
	if !packet.InitEmptyIPv4UDPPacket(pkt, size) {
		panic(fmt.Sprintf("InitEmptyIPv4UDPPacket returned false"))
	}
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	FillEtherHdr(pkt, l2)
	FillIPv4Hdr(pkt, l3)
	FillUDPHdr(pkt, l4)
	pktUDP := (*packet.UDPHdr)(pkt.L4)
	pktIP := (*packet.IPv4Hdr)(pkt.L3)
	pktIP.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pktIP))
	pktUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pktIP, pktUDP, pkt.Data))
}

func generateICMPIPv4(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := &config.Ether
	l3 := &l2.IPv4
	l4 := &l3.ICMP
	size, dataConfig, copyDataFunc := getDataSizeType(&l4.Bytes, rnd)
	if !packet.InitEmptyIPv4ICMPPacket(pkt, size) {
		panic(fmt.Sprintf("InitEmptyIPv4ICMPPacket returned false"))
	}
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	FillEtherHdr(pkt, l2)
	FillIPv4Hdr(pkt, l3)
	FillICMPHdr(pkt, l4, rnd)
	pktICMP := (*packet.ICMPHdr)(pkt.L4)
	pktIP := (*packet.IPv4Hdr)(pkt.L3)
	pktIP.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pktIP))
	pktICMP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(pktIP, pktICMP, pkt.Data))
}

func generatePcap(pkt *packet.Packet, config *PacketConfig, _ *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	pcapConfig := &config.Pcap
	if pcapConfig.FileReader == nil {
		f, err := os.Open(pcapConfig.Path)
		if err != nil {
			panic(fmt.Sprintf("Failed to open pcap file %s", pcapConfig.Path))
		}
		pcapConfig.FileReader = f
		var glHdr packet.PcapGlobHdr
		if err := packet.ReadPcapGlobalHdr(f, &glHdr); err != nil {
			f.Close()
			panic(fmt.Sprintf("Failed to read pcap file header, returned %v", err))
		}
	}
	isEOF, err := pkt.ReadPcapOnePacket(pcapConfig.FileReader)
	if err != nil {
		panic("Failed to read one packet from pcap")
	}
	if isEOF {
		if _, err := pcapConfig.FileReader.Seek(packet.PcapGlobHdrSize, 0); err != nil {
			panic("Failed to parse pcap file header")
		}
		if _, err := pkt.ReadPcapOnePacket(pcapConfig.FileReader); err != nil {
			panic("Failed to read one packet from pcap")
		}
	}
}

func generatePcapInMemory(pkt *packet.Packet, config *PacketConfig, _ *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	pcapConfig := &config.Pcap
	if !pcapConfig.ReachedEOF {
		if pcapConfig.FileReader == nil {
			f, err := os.Open(pcapConfig.Path)
			if err != nil {
				panic(fmt.Sprintf("Failed to open pcap file %s", pcapConfig.Path))
			}
			pcapConfig.FileReader = f
			var glHdr packet.PcapGlobHdr
			if err := packet.ReadPcapGlobalHdr(f, &glHdr); err != nil {
				f.Close()
				panic(fmt.Sprintf("Failed to read pcap file header, returned %v", err))
			}
		}
		isEOF, err := pkt.ReadPcapOnePacket(pcapConfig.FileReader)
		if err != nil {
			panic("Failed to read one packet from pcap")
		}
		if isEOF {
			pcapConfig.FileReader.Close()
			pcapConfig.ReachedEOF = true
		} else {
			data := pkt.GetRawPacketBytes()
			pcapConfig.Packets = append(pcapConfig.Packets, data)
		}
	}
	if pcapConfig.ReachedEOF {
		bytes := pcapConfig.Packets[pcapConfig.NextPacket]
		pcapConfig.NextPacket = (pcapConfig.NextPacket + 1) % len(pcapConfig.Packets)
		ok := packet.GeneratePacketFromByte(pkt, bytes)
		if !ok {
			panic("Failed to generate packet from byte")
		}
	}
}

func FillTCPHdr(pkt *packet.Packet, l4 *TCPConfig, rnd *rand.Rand) {
	emptyPacketTCP := (*packet.TCPHdr)(pkt.L4)
	emptyPacketTCP.SrcPort = packet.SwapBytesUint16(uint16(l4.SPort.Current))
	emptyPacketTCP.DstPort = packet.SwapBytesUint16(uint16(l4.DPort.Current))
	emptyPacketTCP.SentSeq = packet.SwapBytesUint32(l4.Seq.Current)
	emptyPacketTCP.TCPFlags = l4.Flags
	if l4.DPort.Inc != 0 {
		getNextValue(&l4.DPort)
	}
	if l4.SPort.Inc != 0 {
		getNextValue(&l4.SPort)
	}
	getNextSeqNumber(&l4.Seq, rnd)
}

func FillUDPHdr(pkt *packet.Packet, l4 *UDPConfig) {
	emptyPacketUDP := (*packet.UDPHdr)(pkt.L4)
	emptyPacketUDP.SrcPort = packet.SwapBytesUint16(uint16(l4.SPort.Current))
	emptyPacketUDP.DstPort = packet.SwapBytesUint16(uint16(l4.DPort.Current))
	getNextValue(&l4.DPort)
	getNextValue(&l4.SPort)
}

func FillICMPHdr(pkt *packet.Packet, l4 *ICMPConfig, rnd *rand.Rand) {
	emptyPacketICMP := (*packet.ICMPHdr)(pkt.L4)
	emptyPacketICMP.Type = l4.Type
	emptyPacketICMP.Code = l4.Code
	emptyPacketICMP.Identifier = l4.Identifier
	emptyPacketICMP.SeqNum = packet.SwapBytesUint16(uint16(l4.Seq.Current))
	getNextSeqNumber(&l4.Seq, rnd)
}

func FillIPv4Hdr(pkt *packet.Packet, l3 *IPv4Config) {
	pktIP := (*packet.IPv4Hdr)(pkt.L3)
	pktIP.SrcAddr = packet.SwapBytesIPv4Addr(types.IPv4Address(l3.SAddr.Current))
	pktIP.DstAddr = packet.SwapBytesIPv4Addr(types.IPv4Address(l3.DAddr.Current))
	getNextValue(&l3.DAddr)
	getNextValue(&l3.SAddr)
}

// SwapBytesUint32 swaps uint32 in Little Endian and Big Endian
func SwapBytesUint64(x uint64) uint64 {
	return ((x & 0x00000000000000ff) << 40) | ((x & 0x000000000000ff00) << 24) | ((x & 0x0000000000ff0000) << 8) |
		((x & 0x00000000ff000000) >> 8) | ((x & 0x0000ff0000000000) >> 40) | ((x & 0x000000ff00000000) >> 24)
}

func FillEtherHdr(pkt *packet.Packet, l2 *EtherConfig) {
	if l2.VLAN != nil {
		addVLAN(pkt, l2.VLAN.TCI)
	}
	t := pkt.Ether.EtherType
	*(*uint64)(unsafe.Pointer(&pkt.Ether.DAddr[0])) = SwapBytesUint64(l2.DAddr.Current)
	*(*uint64)(unsafe.Pointer(&pkt.Ether.SAddr[0])) = SwapBytesUint64(l2.SAddr.Current)
	pkt.Ether.EtherType = t
	getNextValue(&l2.DAddr)
	getNextValue(&l2.SAddr)
}

// faster version of packet.AddVLANTag, can be used only
// when ether src and dst are not set, but ether type is
// (most InitEmptyPacket functions do so).
func addVLAN(pkt *packet.Packet, tag uint16) {
	if !pkt.EncapsulateHead(0, 4) {
		panic("failed to add vlan tag, EncapsulateHead returned false")
	}
	pkt.Ether.EtherType = packet.SwapBytesUint16(types.VLANNumber)
	vhdr := pkt.GetVLAN()
	if vhdr == nil {
		panic("failed to get vlan, GetVLAN returned nil")
	}
	vhdr.TCI = packet.SwapBytesUint16(tag)
}
