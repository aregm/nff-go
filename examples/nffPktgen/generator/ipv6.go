// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package generator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"strings"

	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

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

func getNextAddr(addr *AddrIPv6Range) []uint8 {
	addAddr(&(addr.Current), addr.Inc)
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

func generateIPv6(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := &config.Ether
	l3 := &l2.IPv6
	size, dataConfig, copyDataFunc := getDataSizeType(&l3.Bytes, rnd)
	if !packet.InitEmptyIPv6Packet(pkt, size) {
		panic(fmt.Sprintf("InitEmptyIPv6Packet returned false"))
	}
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	FillEtherHdr(pkt, l2)
	FillIPv6Hdr(pkt, l3)
}

func generateTCPIPv6(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := &config.Ether
	l3 := &l2.IPv6
	l4 := &l3.TCP
	size, dataConfig, copyDataFunc := getDataSizeType(&l4.Bytes, rnd)
	if !packet.InitEmptyIPv6TCPPacket(pkt, size) {
		panic(fmt.Sprintf("InitEmptyIPv6TCPPacket returned false"))
	}
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	FillEtherHdr(pkt, l2)
	FillIPv6Hdr(pkt, l3)
	FillTCPHdr(pkt, l4, rnd)
	pktTCP := (*packet.TCPHdr)(pkt.L4)
	pktIP := (*packet.IPv6Hdr)(pkt.L3)
	pktTCP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6TCPChecksum(pktIP, pktTCP, pkt.Data))
}

func generateUDPIPv6(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := &config.Ether
	l3 := &l2.IPv6
	l4 := &l3.UDP
	size, dataConfig, copyDataFunc := getDataSizeType(&l4.Bytes, rnd)
	if !packet.InitEmptyIPv6UDPPacket(pkt, size) {
		panic(fmt.Sprintf("InitEmptyIPv6UDPPacket returned false"))
	}
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	FillEtherHdr(pkt, l2)
	FillIPv6Hdr(pkt, l3)
	FillUDPHdr(pkt, l4)
	pktUDP := (*packet.UDPHdr)(pkt.L4)
	pktIP := (*packet.IPv6Hdr)(pkt.L3)
	pktUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv6UDPChecksum(pktIP, pktUDP, pkt.Data))
}

func generateICMPIPv6(pkt *packet.Packet, config *PacketConfig, rnd *rand.Rand) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	l2 := &config.Ether
	l3 := &l2.IPv6
	l4 := &l3.ICMP
	size, dataConfig, copyDataFunc := getDataSizeType(&l4.Bytes, rnd)
	if !packet.InitEmptyIPv6ICMPPacket(pkt, size) {
		panic(fmt.Sprintf("InitEmptyIPv6ICMPPacket returned false"))
	}
	copyDataFunc(dataConfig, size, rnd, pkt.Data)
	FillEtherHdr(pkt, l2)
	FillIPv6Hdr(pkt, l3)
	FillICMPHdr(pkt, l4, rnd)
	pktICMP := (*packet.ICMPHdr)(pkt.L4)
	pktIP := (*packet.IPv6Hdr)(pkt.L3)
	pktICMP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6ICMPChecksum(pktIP, pktICMP, pkt.Data))
}

func FillIPv6Hdr(pkt *packet.Packet, l3 *IPv6Config) {
	pktIP := (*packet.IPv6Hdr)(pkt.L3)
	copyAddr(pktIP.SrcAddr[:], getNextAddr(&(l3.SAddr)), types.IPv6AddrLen)
	copyAddr(pktIP.DstAddr[:], getNextAddr(&(l3.DAddr)), types.IPv6AddrLen)
}

// AddrRange describes range of addresses.
type AddrIPv6Range struct {
	Min     []byte
	Max     []byte
	Current []byte
	Inc     []byte
}

// IPv6Config configures ip header.
type IPv6Config struct {
	SAddr AddrIPv6Range // source address
	DAddr AddrIPv6Range // destination address
	DType DataType
	TCP   TCPConfig
	UDP   UDPConfig
	ICMP  ICMPConfig
	Bytes RawBytes
}

func (ipv6 *IPv6Config) UnmarshalJSON(data []byte) error {
	var in map[string]interface{}
	err := json.Unmarshal(data, &in)
	if err != nil {
		return err
	}
	*ipv6, err = parseIPv6Hdr(in)
	return err
}

func parseIPv6Hdr(in map[string]interface{}) (IPv6Config, error) {
	ipHdr := IPv6Config{DAddr: AddrIPv6Range{}, SAddr: AddrIPv6Range{}}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "saddr":
			saddr, err := parseIPv6Addr(v)
			if err != nil {
				return IPv6Config{}, fmt.Errorf("parseIPv6Addr for ip saddr returned: %v", err)
			}
			ipHdr.SAddr = saddr
		case "daddr":
			daddr, err := parseIPv6Addr(v)
			if err != nil {
				return IPv6Config{}, fmt.Errorf("parseIPv6Addr for ip daddr returned: %v", err)
			}
			ipHdr.DAddr = daddr
		case "tcp":
			tcpConf, err := parseTCPHdr(v.(map[string]interface{}))
			if err != nil {
				return IPv6Config{}, fmt.Errorf("parseTCPHdr returned %v", err)
			}
			ipHdr.TCP = tcpConf
			ipHdr.DType = TCPHDR
			break
		case "udp":
			udpConf, err := parseUDPHdr(v.(map[string]interface{}))
			if err != nil {
				return IPv6Config{}, fmt.Errorf("parseUDPHdr returned %v", err)
			}
			ipHdr.UDP = udpConf
			ipHdr.DType = UDPHDR
			break
		case "icmp":
			icmpConf, err := parseICMPHdr(v.(map[string]interface{}))
			if err != nil {
				return IPv6Config{}, fmt.Errorf("parseICMPHdr returned %v", err)
			}
			ipHdr.ICMP = icmpConf
			ipHdr.DType = ICMPHDR
			break
		default:
			data, err := parseData(map[string]interface{}{k: v})
			if err != nil {
				return IPv6Config{}, fmt.Errorf("parseData for ip returned: %v", err)
			}
			ipHdr.Bytes = data
			ipHdr.DType = DATA
			break
		}
	}
	return ipHdr, nil
}

func parseRawIPv6Addr(rawAddr string) ([]uint8, error) {
	addr := net.ParseIP(rawAddr)
	if addr == nil {
		return nil, fmt.Errorf("parsing ip addr could not parse address for %s", rawAddr)
	}
	return addr, nil
}

func parseIPv6Addr(value interface{}) (AddrIPv6Range, error) {
	switch v2 := value.(type) {
	case map[string]interface{}:
		for k, v := range v2 {
			switch strings.ToLower(k) {
			case "range":
				addrRange, err := parseAddrIPv6Range(v.(map[string]interface{}), parseRawIPv6Addr)
				if err != nil {
					return AddrIPv6Range{}, fmt.Errorf("parseAddrIPv6Range returned: %v", err)
				}
				return addrRange, nil
			default:
				return AddrIPv6Range{}, fmt.Errorf("unknown key in ip addr: %s", k)
			}
		}
	case string:
		saddr, err := parseRawIPv6Addr(v2)
		if err != nil {
			return AddrIPv6Range{}, fmt.Errorf("parsing ip addr returned: %v", err)
		}
		ret := AddrIPv6Range{}
		ret.Min = make([]byte, len(saddr))
		copy(ret.Min, saddr)
		ret.Max = make([]byte, len(saddr))
		copy(ret.Max, saddr)
		ret.Current = make([]byte, len(saddr))
		copy(ret.Current, saddr)
		return ret, nil
	}
	return AddrIPv6Range{}, fmt.Errorf("unknown type")
}

type fn6 func(string) ([]uint8, error)

func parseAddrIPv6Range(in map[string]interface{}, parseFunc fn6) (AddrIPv6Range, error) {
	addr := AddrIPv6Range{}
	wasMin, wasMax, wasStart, wasIncr := false, false, false, false
	for k, v := range in {
		switch strings.ToLower(k) {
		case "min":
			min, err := parseFunc(v.(string))
			if err != nil {
				return AddrIPv6Range{}, fmt.Errorf("parsing min returned: %v", err)
			}
			addr.Min = make([]byte, len(min))
			copy(addr.Min, min)
			wasMin = true
		case "max":
			max, err := parseFunc(v.(string))
			if err != nil {
				return AddrIPv6Range{}, fmt.Errorf("parsing max returned: %v", err)
			}
			addr.Max = make([]byte, len(max))
			copy(addr.Max, max)
			wasMax = true
		case "start":
			start, err := parseFunc(v.(string))
			if err != nil {
				return AddrIPv6Range{}, fmt.Errorf("parsing start returned: %v", err)
			}
			addr.Current = make([]byte, len(start))
			copy(addr.Current, start)
			wasStart = true
		case "incr":
			addr.Inc = big.NewInt((int64)(v.(float64))).Bytes()
			wasIncr = true
		default:
			return AddrIPv6Range{}, fmt.Errorf("unknown key %s", k)
		}
	}
	if !wasMax || !wasMin {
		return AddrIPv6Range{}, fmt.Errorf("Min and max values should be given for range")
	}
	if bytes.Compare(addr.Max, addr.Min) < 0 {
		return AddrIPv6Range{}, fmt.Errorf("Min value should be less than Max")
	}
	if !wasStart {
		addr.Current = make([]byte, len(addr.Min))
		copy(addr.Current, addr.Min)
	}

	if bytes.Compare(addr.Current, addr.Min) < 0 || bytes.Compare(addr.Current, addr.Max) > 0 {
		return AddrIPv6Range{}, fmt.Errorf(fmt.Sprintf("Start value should be between min and max: start=%v, min=%v, max=%v", addr.Current, addr.Min, addr.Max))
	}
	if !wasIncr {
		addr.Inc = []byte{1}
	}
	return addr, nil
}
