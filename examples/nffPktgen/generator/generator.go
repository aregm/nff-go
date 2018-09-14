// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package generator

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sync/atomic"
	"unsafe"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var gen generator

type generator struct {
	count uint64
}

// GetGenerator returns generator struct pointer
// generator is single and created only once
func GetGenerator() *generator {
	return &gen
}

// GetGeneratedNumber returns a number of packets generated
func (g *generator) GetGeneratedNumber() uint64 {
	return atomic.LoadUint64(&(g.count))
}

// ReadConfig function reads and parses config file.
func ReadConfig(fileName string) ([]*MixConfig, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("opening file failed with: %v ", err)
	}
	cfg, err := ParseConfig(f)
	if err != nil {
		return nil, fmt.Errorf("parsing config failed with: %v", err)
	}
	return cfg, nil
}

func addAddr(a *[]byte, b []byte) {
	var offset int
	aLen := len(*a)
	bLen := len(b)
	if aLen < bLen {
		add := make([]byte, bLen-aLen)
		*a = append(add, *a...)
	} else {
		offset = aLen - bLen
	}
	var next byte
	for i := bLen - 1; i >= 0; i-- {
		add := (*a)[i+offset] + b[i] + next
		if add > 255 {
			next = 1
			(*a)[i+offset] = byte(255) - add
		} else {
			(*a)[i+offset] = add
			next = 0
		}
	}
}

func getNextAddr(addr *AddrRange) []uint8 {
	addAddr(&(addr.Current), addr.Incr)
	// if current < min or current > max, copy min to current
	if bytes.Compare(addr.Current, addr.Min) < 0 || bytes.Compare(addr.Current, addr.Max) > 0 {
		copy(addr.Current, addr.Min)
	}
	return addr.Current
}

func copyAddr(destination []uint8, source []uint8, size int) {
	if size < len(source) {
		copy(destination[:], source[len(source)-size:])
	} else {
		copy(destination[size-len(source):], source[:])
	}
}

func getNextPort(port *PortRange) (nextPort uint16) {
	if port.Current < port.Min || port.Current > port.Max {
		port.Current = port.Min
	}
	nextPort = port.Current
	port.Current += port.Incr
	return nextPort
}

func getNextSeqNumber(seq *Sequence, rnd *rand.Rand) (nextSeqNum uint32) {
	nextSeqNum = seq.Next
	if seq.Type == RANDOM {
		seq.Next = rnd.Uint32()
	} else if seq.Type == INCREASING {
		seq.Next++
	}
	return nextSeqNum
}

type dataCopier func(unsafe.Pointer, uint, *rand.Rand, unsafe.Pointer)

func copyRaw(configuration unsafe.Pointer, size uint, rnd *rand.Rand, copyTo unsafe.Pointer) {
	data := (*Raw)(configuration)
	copy((*[1 << 30]uint8)(copyTo)[0:size], ([]uint8(data.Data)))
}

func copyRand(configuration unsafe.Pointer, size uint, rnd *rand.Rand, copyTo unsafe.Pointer) {
	packetData := (*[1 << 30]byte)(copyTo)[0:size]
	for i := range packetData {
		packetData[i] = byte(rnd.Int())
	}
}

func getDataSizeType(configuration unsafe.Pointer, dtype DataType, rnd *rand.Rand) (uint, unsafe.Pointer, dataCopier) {
	switch dtype {
	case RAWDATA:
		data := (*Raw)(configuration)
		return uint(len(data.Data)), configuration, copyRaw
	case RANDDATA:
		data := (*RandBytes)(configuration)
		maxZise := data.Size + data.Deviation
		minSize := data.Size - data.Deviation
		randSize := uint(rnd.Float64()*float64(maxZise-minSize) + float64(minSize))
		return randSize, configuration, copyRand
	case PDISTDATA:
		data := (*[]PDistEntry)(configuration)
		prob := 0.0
		rndN := math.Abs(rnd.Float64())
		maxProb := PDistEntry{Probability: 0}
		for _, item := range *data {
			prob += item.Probability
			if rndN <= prob {
				return getDataSizeType(item.Data, item.DType, rnd)
			}
			if item.Probability > maxProb.Probability {
				maxProb = item
			}
		}
		if prob <= 0 || prob > 1 {
			panic(fmt.Sprintf("sum of pdist probabilities is invalid, %f", prob))
		}
		// get the variant with max prob
		// if something went wrong and rand did not match any prob
		// may happen if sum of prob was not 1
		return getDataSizeType(maxProb.Data, maxProb.DType, rnd)
	}
	panic(fmt.Sprintf("unknown data type"))
}

func getGenerator(configuration *PacketConfig) (func(*packet.Packet, *PacketConfig, *rand.Rand), error) {
	switch configuration.DType {
	case ETHERHDR:
		l2 := (*EtherConfig)(configuration.Data)
		switch l2.DType {
		case IPHDR:
			l3 := (*IPConfig)(l2.Data)
			switch l3.DType {
			case TCPHDR:
				return generateTCPIP, nil
			case UDPHDR:
				return generateUDPIP, nil
			case ICMPHDR:
				return generateICMPIP, nil
			case RAWDATA, RANDDATA, PDISTDATA:
				return generateIP, nil
			default:
				return nil, fmt.Errorf("unknown packet l4 configuration")
			}
		case ARPHDR:
			return generateARP, nil
		case RAWDATA, RANDDATA, PDISTDATA:
			return generateEther, nil
		default:
			return nil, fmt.Errorf("unknown packet l3 configuration")
		}
	default:
		return nil, fmt.Errorf("unknown packet l2 configuration")
	}
}

// one unit for each mix
type generatorTableUnit struct {
	have, need    uint32
	generatorFunc func(*packet.Packet, *PacketConfig, *rand.Rand)
	config        *PacketConfig
}

func (gtu *generatorTableUnit) String() string {
	return fmt.Sprintf("need: %d, config: %v\n", gtu.need, gtu.config)
}

type genParameters struct {
	table  []generatorTableUnit
	next   uint32
	length uint32
	rnd    *rand.Rand
}

func (gp genParameters) Copy() interface{} {
	ret := new(genParameters)
	ret.table = make([]generatorTableUnit, len(gp.table))
	copy(ret.table, gp.table)
	ret.length = gp.length
	ret.rnd = rand.New(rand.NewSource(13))
	return ret
}

func (gp genParameters) Delete() {
}

// GetContext gets generator context according to config
func GetContext(mixConfig []*MixConfig) (*genParameters, error) {
	var t []generatorTableUnit
	for _, packetConfig := range mixConfig {
		genFunc, err := getGenerator(packetConfig.Config)
		if err != nil {
			return nil, err
		}
		tu := generatorTableUnit{have: 0, need: packetConfig.Quantity, generatorFunc: genFunc, config: packetConfig.Config}
		t = append(t, tu)
	}
	ret := new(genParameters)
	ret.table = t
	ret.length = uint32(len(t))
	ret.rnd = rand.New(rand.NewSource(13))
	return ret, nil
}

// Generate is a main generatior func
func Generate(pkt *packet.Packet, context flow.UserContext) {
	genP := context.(*genParameters)
	if genP.length > 1 {
		if genP.table[genP.next].have == genP.table[genP.next].need {
			genP.table[genP.next].have = 0
			if genP.next+1 < genP.length {
				genP.next++
			} else {
				genP.next = 0
			}
		}
	}
	genP.table[genP.next].generatorFunc(pkt, genP.table[genP.next].config, genP.rnd)
	atomic.AddUint64(&(gen.count), 1)
	genP.table[genP.next].have++
}

func generateEther(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := (*EtherConfig)(config.Data)
	size, dataConfig, copyDataFunc := getDataSizeType(l2.Data, l2.DType, rnd)

	if !packet.InitEmptyPacket(pkt, size) {
		panic(fmt.Sprintf("InitEmptyPacket failed"))
	}
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	fillEtherHdr(pkt, l2)
}

func generateIP(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := (*EtherConfig)(config.Data)
	l3 := (*IPConfig)(l2.Data)
	size, dataConfig, copyDataFunc := getDataSizeType(l3.Data, l3.DType, rnd)
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
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	fillEtherHdr(pkt, l2)
	fillIPHdr(pkt, l3)
	if l3.Version == 4 {
		pktIP := (*packet.IPv4Hdr)(pkt.L3)
		pktIP.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pktIP))
	}
}

func To4(addr []byte) []byte {
	if len(addr) > common.IPv4AddrLen {
		return addr[len(addr)-common.IPv4AddrLen:]
	}
	return addr
}

func generateARP(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := (*EtherConfig)(config.Data)
	l3 := (*ARPConfig)(l2.Data)
	var SHA, THA [common.EtherAddrLen]uint8
	copyAddr(SHA[:], getNextAddr(&(l3.SHA)), common.EtherAddrLen)
	SPA := binary.LittleEndian.Uint32(To4(getNextAddr(&(l3.SPA))))
	switch l3.Operation {
	case packet.ARPRequest:
		if l3.Gratuitous {
			if !packet.InitGARPAnnouncementRequestPacket(pkt, SHA, SPA) {
				panic(fmt.Sprintf("InitGARPAnnouncementRequestPacket returned false"))
			}
		} else {
			TPA := binary.LittleEndian.Uint32(To4(getNextAddr(&(l3.TPA))))
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
			copyAddr(THA[:], getNextAddr(&(l3.THA)), common.EtherAddrLen)
			TPA := binary.LittleEndian.Uint32(To4(getNextAddr(&(l3.TPA))))
			if !packet.InitARPReplyPacket(pkt, SHA, THA, SPA, TPA) {
				panic(fmt.Sprintf("InitARPReplyPacket returned false"))
			}
		}
	default:
		panic(fmt.Sprintf("unsupported operation code: %d", l3.Operation))
	}
	copyAddr(pkt.Ether.DAddr[:], getNextAddr(&(l2.DAddr)), common.EtherAddrLen)
	if l2.VLAN != nil {
		if !pkt.AddVLANTag(l2.VLAN.TCI) {
			panic("failed to add vlan tag to arp packet")
		}
	}
}

func generateTCPIP(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := (*EtherConfig)(config.Data)
	l3 := (*IPConfig)(l2.Data)
	l4 := (*TCPConfig)(l3.Data)
	size, dataConfig, copyDataFunc := getDataSizeType(l4.Data, l4.DType, rnd)
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
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	fillEtherHdr(pkt, l2)
	fillIPHdr(pkt, l3)
	fillTCPHdr(pkt, l4, rnd)
	pktTCP := (*packet.TCPHdr)(pkt.L4)
	if l3.Version == 4 {
		pktIP := (*packet.IPv4Hdr)(pkt.L3)
		pktIP.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pktIP))
		pktTCP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(pktIP, pktTCP, pkt.Data))
	} else if l3.Version == 6 {
		pktIP := (*packet.IPv6Hdr)(pkt.L3)
		pktTCP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6TCPChecksum(pktIP, pktTCP, pkt.Data))
	}
}

func generateUDPIP(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := (*EtherConfig)(config.Data)
	l3 := (*IPConfig)(l2.Data)
	l4 := (*UDPConfig)(l3.Data)
	size, dataConfig, copyDataFunc := getDataSizeType(l4.Data, l4.DType, rnd)
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
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	fillEtherHdr(pkt, l2)
	fillIPHdr(pkt, l3)
	fillUDPHdr(pkt, l4)
	pktUDP := (*packet.UDPHdr)(pkt.L4)
	if l3.Version == 4 {
		pktIP := (*packet.IPv4Hdr)(pkt.L3)
		pktIP.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pktIP))
		pktUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pktIP, pktUDP, pkt.Data))
	} else if l3.Version == 6 {
		pktIP := (*packet.IPv6Hdr)(pkt.L3)
		pktUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv6UDPChecksum(pktIP, pktUDP, pkt.Data))
	}
}

func generateICMPIP(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := (*EtherConfig)(config.Data)
	l3 := (*IPConfig)(l2.Data)
	l4 := (*ICMPConfig)(l3.Data)
	size, dataConfig, copyDataFunc := getDataSizeType(l4.Data, l4.DType, rnd)
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
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	fillEtherHdr(pkt, l2)
	fillIPHdr(pkt, l3)
	fillICMPHdr(pkt, l4, rnd)
	pktICMP := (*packet.ICMPHdr)(pkt.L4)
	if l3.Version == 4 {
		pktIP := (*packet.IPv4Hdr)(pkt.L3)
		pktIP.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pktIP))
		pktICMP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(pktIP, pktICMP, pkt.Data))
	} else if l3.Version == 6 {
		pktIP := (*packet.IPv6Hdr)(pkt.L3)
		pktICMP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6ICMPChecksum(pktIP, pktICMP))
	}
}

func fillTCPHdr(pkt *packet.Packet, l4 *TCPConfig, rnd *rand.Rand) {
	emptyPacketTCP := (*packet.TCPHdr)(pkt.L4)
	emptyPacketTCP.SrcPort = packet.SwapBytesUint16(getNextPort(&(l4.SPort)))
	emptyPacketTCP.DstPort = packet.SwapBytesUint16(getNextPort(&(l4.DPort)))
	emptyPacketTCP.SentSeq = packet.SwapBytesUint32(getNextSeqNumber((&l4.Seq), rnd))
	emptyPacketTCP.TCPFlags = l4.Flags
}

func fillUDPHdr(pkt *packet.Packet, l4 *UDPConfig) {
	emptyPacketUDP := (*packet.UDPHdr)(pkt.L4)
	emptyPacketUDP.SrcPort = packet.SwapBytesUint16(getNextPort(&(l4.SPort)))
	emptyPacketUDP.DstPort = packet.SwapBytesUint16(getNextPort(&(l4.DPort)))
}

func fillICMPHdr(pkt *packet.Packet, l4 *ICMPConfig, rnd *rand.Rand) {
	emptyPacketICMP := (*packet.ICMPHdr)(pkt.L4)
	emptyPacketICMP.Type = l4.Type
	emptyPacketICMP.Code = l4.Code
	emptyPacketICMP.Identifier = l4.Identifier
	emptyPacketICMP.SeqNum = packet.SwapBytesUint16(uint16(getNextSeqNumber(&(l4.Seq), rnd)))
}

func fillIPHdr(pkt *packet.Packet, l3 *IPConfig) {
	if l3.Version == 4 {
		pktIP := (*packet.IPv4Hdr)(pkt.L3)
		pktIP.SrcAddr = binary.LittleEndian.Uint32(To4(getNextAddr(&(l3.SAddr))))
		pktIP.DstAddr = binary.LittleEndian.Uint32(To4(getNextAddr(&(l3.DAddr))))
		return
	}
	pktIP := (*packet.IPv6Hdr)(pkt.L3)
	copyAddr(pktIP.SrcAddr[:], getNextAddr(&(l3.SAddr)), common.IPv6AddrLen)
	copyAddr(pktIP.DstAddr[:], getNextAddr(&(l3.DAddr)), common.IPv6AddrLen)
}

func fillEtherHdr(pkt *packet.Packet, l2 *EtherConfig) {
	if l2.VLAN != nil {
		addVLAN(pkt, l2.VLAN.TCI)
	}
	copyAddr(pkt.Ether.DAddr[:], getNextAddr(&(l2.DAddr)), common.EtherAddrLen)
	copyAddr(pkt.Ether.SAddr[:], getNextAddr(&(l2.SAddr)), common.EtherAddrLen)
}

// faster version of packet.AddVLANTag, can be used only
// when ether src and dst are not set, but ether type is
// (most InitEmptyPacket functions do so).
func addVLAN(pkt *packet.Packet, tag uint16) {
	if !pkt.EncapsulateHead(0, 4) {
		panic("failed to add vlan tag, EncapsulateHead returned false")
	}
	pkt.Ether.EtherType = packet.SwapBytesUint16(common.VLANNumber)
	vhdr := pkt.GetVLAN()
	if vhdr == nil {
		panic("failed to get vlan, GetVLAN returned nil")
	}
	vhdr.TCI = packet.SwapBytesUint16(tag)
}
