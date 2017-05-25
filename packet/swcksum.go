// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	. "github.com/intel-go/yanff/common"
	"unsafe"
)

// Calculates checksum of memory for a given pointer. Length and
// offset are in bytes. Offset is signed, so negative offset is
// possible. Checksum is calculated in uint16 words. Returned is
// checksum with carry, so carry should be added and value negated for
// use as network checksum.
func calculateDataChecksum(ptr unsafe.Pointer, length, offset int) uint32 {
	var sum uint32 = 0
	uptr := uintptr(ptr) + uintptr(offset)

	slice := (*[1 << 30]uint16)(unsafe.Pointer(uptr))[0 : length/2]
	for i := range slice {
		sum += uint32(SwapBytesUint16(slice[i]))
	}

	if length&1 != 0 {
		sum += uint32(*(*byte)(unsafe.Pointer(uptr + uintptr(length-1))) << 8)
	}

	return sum
}

func fixChecksum(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return uint16(^sum)
}

// Calculates checksum of IP header
func CalculateIPv4Checksum(p *Packet) uint16 {
	var sum uint32
	hdr := p.IPv4

	sum = uint32(hdr.VersionIhl<<8) + uint32(hdr.TypeOfService) +
		uint32(SwapBytesUint16(hdr.TotalLength)) +
		uint32(SwapBytesUint16(hdr.PacketID)) +
		uint32(SwapBytesUint16(hdr.FragmentOffset)) +
		uint32(hdr.TimeToLive<<8) + uint32(hdr.NextProtoID) +
		uint32(SwapBytesUint16(uint16(hdr.SrcAddr>>16))) +
		uint32(SwapBytesUint16(uint16(hdr.SrcAddr))) +
		uint32(SwapBytesUint16(uint16(hdr.DstAddr>>16))) +
		uint32(SwapBytesUint16(uint16(hdr.DstAddr)))

	return fixChecksum(sum)
}

func calculateIPv4AddrChecksum(hdr *IPv4Hdr) uint32 {
	return uint32(SwapBytesUint16(uint16(hdr.SrcAddr>>16))) +
		uint32(SwapBytesUint16(uint16(hdr.SrcAddr))) +
		uint32(SwapBytesUint16(uint16(hdr.DstAddr>>16))) +
		uint32(SwapBytesUint16(uint16(hdr.DstAddr)))
}

func CalculateIPv4UDPChecksum(p *Packet) uint16 {
	hdr := p.IPv4
	udp := p.UDP
	dataLength := SwapBytesUint16(hdr.TotalLength) - IPv4MinLen

	sum := calculateDataChecksum(p.Data, int(dataLength-UDPLen), 0)

	sum += calculateIPv4AddrChecksum(hdr) +
		uint32(hdr.NextProtoID) +
		uint32(hdr.TotalLength) +
		uint32(SwapBytesUint16(udp.SrcPort)) +
		uint32(SwapBytesUint16(udp.DstPort)) +
		uint32(dataLength-UDPLen)
	return fixChecksum(sum)
}

func calculateTCPChecksum(tcp *TCPHdr) uint32 {
	return uint32(SwapBytesUint16(tcp.SrcPort)) +
		uint32(SwapBytesUint16(tcp.DstPort)) +
		uint32(SwapBytesUint16(uint16(tcp.SentSeq>>16))) +
		uint32(SwapBytesUint16(uint16(tcp.SentSeq))) +
		uint32(SwapBytesUint16(uint16(tcp.RecvAck>>16))) +
		uint32(SwapBytesUint16(uint16(tcp.RecvAck))) +
		uint32(tcp.DataOff<<8) +
		uint32(tcp.TCPFlags) +
		uint32(SwapBytesUint16(tcp.RxWin)) +
		uint32(SwapBytesUint16(tcp.TCPUrp))
}

func CalculateIPv4TCPChecksum(p *Packet) uint16 {
	hdr := p.IPv4
	tcp := p.TCP
	dataLength := SwapBytesUint16(hdr.TotalLength) - IPv4MinLen

	sum := calculateDataChecksum(p.Data, int(dataLength-TCPMinLen), 0)

	sum += calculateIPv4AddrChecksum(hdr) +
		uint32(hdr.NextProtoID) +
		uint32(dataLength) +
		calculateTCPChecksum(tcp)

	return fixChecksum(sum)
}

func calculateIPv6AddrChecksum(hdr *IPv6Hdr) uint32 {
	return uint32(uint16(hdr.SrcAddr[0]<<8)|uint16(hdr.SrcAddr[1])) +
		uint32(uint16(hdr.SrcAddr[2]<<8)|uint16(hdr.SrcAddr[3])) +
		uint32(uint16(hdr.SrcAddr[4]<<8)|uint16(hdr.SrcAddr[5])) +
		uint32(uint16(hdr.SrcAddr[6]<<8)|uint16(hdr.SrcAddr[7])) +
		uint32(uint16(hdr.SrcAddr[8]<<8)|uint16(hdr.SrcAddr[9])) +
		uint32(uint16(hdr.SrcAddr[10]<<8)|uint16(hdr.SrcAddr[11])) +
		uint32(uint16(hdr.SrcAddr[12]<<8)|uint16(hdr.SrcAddr[13])) +
		uint32(uint16(hdr.SrcAddr[14]<<8)|uint16(hdr.SrcAddr[15])) +
		uint32(uint16(hdr.DstAddr[0]<<8)|uint16(hdr.DstAddr[1])) +
		uint32(uint16(hdr.DstAddr[2]<<8)|uint16(hdr.DstAddr[3])) +
		uint32(uint16(hdr.DstAddr[4]<<8)|uint16(hdr.DstAddr[5])) +
		uint32(uint16(hdr.DstAddr[6]<<8)|uint16(hdr.DstAddr[7])) +
		uint32(uint16(hdr.DstAddr[8]<<8)|uint16(hdr.DstAddr[9])) +
		uint32(uint16(hdr.DstAddr[10]<<8)|uint16(hdr.DstAddr[11])) +
		uint32(uint16(hdr.DstAddr[12]<<8)|uint16(hdr.DstAddr[13])) +
		uint32(uint16(hdr.DstAddr[14]<<8)|uint16(hdr.DstAddr[15]))
}

func CalculateIPv6UDPChecksum(p *Packet) uint16 {
	hdr := p.IPv6
	udp := p.UDP
	dataLength := SwapBytesUint16(hdr.PayloadLen) - IPv4MinLen

	sum := calculateDataChecksum(p.Data, int(dataLength-UDPLen), 0)

	sum += calculateIPv6AddrChecksum(hdr) +
		uint32(hdr.PayloadLen) +
		uint32(hdr.Proto) +
		uint32(SwapBytesUint16(udp.SrcPort)) +
		uint32(SwapBytesUint16(udp.DstPort)) +
		uint32(dataLength-UDPLen)

	return fixChecksum(sum)
}

func CalculateIPv6TCPChecksum(p *Packet) uint16 {
	hdr := p.IPv6
	tcp := p.TCP
	dataLength := SwapBytesUint16(hdr.PayloadLen) - IPv4MinLen

	sum := calculateDataChecksum(p.Data, int(dataLength-TCPMinLen), 0)

	sum += calculateIPv6AddrChecksum(hdr) +
		uint32(dataLength) +
		uint32(hdr.Proto) +
		calculateTCPChecksum(tcp)

	return fixChecksum(sum)
}
