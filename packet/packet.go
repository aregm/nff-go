// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package packet provides functionality for fast parsing and generating
// of packets with known structure.
// The following header types are supported:
//	* L2 Ethernet
//	* L3 IPv4 and IPv6
//	* L4 TCP and UDP
// At the moment IPv6 is supported without extension headers.
//
// For performance
// reasons YANFF provides a set of functions each of them parse exact network level.
//
// Packet parsing
//
// Family of parsing functions can parse packets with known structure of headers
// and parse exactly required protocols.
//
// YANFF provides two groups of parsing functions:
// conditional and unconditional parsing functions.
//
// Unconditional parsing functions are used to parse exactly required protocols. They use constant offsets and
// pointer arithmetic to get required pointers. There are no checks for correctness because of performance reasons.
//
// Conditional parsing functions are used to parse any supported protocols.
//
// Packet generation
//
// Packets should be placed in special memory to be sent, so user should use
// additional functions to generate packets. There are two possibilities to do this:
//		PacketFromByte function
// This function get slice of bytes of any size. Returns packet which contains only these bytes.
//		CreateEmpty function family
// There is family of functions to generate empty packets of predefined
// size with known header types. All these functions return empty but parsed
// packet with required protocol headers and preallocated space for payload.
// All these functions get size of payload as argument. After using one of
// this functions user can fill any required fields headers of the packet and
// also fill payload.
package packet

import (
	"fmt"
	"github.com/intel-go/yanff/low"
	"unsafe"
)

var mbufStructSize uintptr

func init() {
	var t1 low.Mbuf
	mbufStructSize = unsafe.Sizeof(t1)
	var t2 Packet
	packetStructSize := unsafe.Sizeof(t2)
	low.SetPacketStructSize(int(packetStructSize))
}

// TODO Add function to write user data after headers and set "data" field

// Supported EtherType for L2
const (
	IPV4Number = 0x0800
	IPV6Number = 0x86dd
)

// Supported L4 types
const (
	IPNumber  = 0x04
	TCPNumber = 0x06
	UDPNumber = 0x11
)

// Length of addresses.
const (
	EtherAddrLen = 6
	IPv6AddrLen  = 16
)

// These constants keep length of supported headers in bytes.
//
// IPv6Len - minimum length of IPv6 header in bytes. It can be higher and it
// is not determined inside packet. Only default minimum size is used.
//
// IPv4MinLen and TCPMinLen are used only in packet generation functions.
//
// In parsing we take actual length of TCP header from DataOff field and length of
// IPv4 take from Ihl field.
const (
	EtherLen   = 14
	IPv4MinLen = 20
	IPv6Len    = 40
	TCPMinLen  = 20
	UDPLen     = 8
)

// EtherIPv6Len is used in packet parsing only when we sure that
// the next protocol is TCP or UDP.
const EtherIPv6Len = EtherLen + IPv6Len

// These structures must be consistent with these C duplications
// L2 header from DPDK: lib/librte_ether/rte_ehter.h
type EtherHdr struct {
	DAddr     [EtherAddrLen]uint8 // Destination address
	SAddr     [EtherAddrLen]uint8 // Source address
	EtherType uint16              // Frame type
}

func (hdr *EtherHdr) String() string {
	r0 := "L2 protocol: Ethernet\n"
	s := hdr.SAddr
	r1 := fmt.Sprintf("Ethernet Source: %02x:%02x:%02x:%02x:%02x:%02x\n", s[0], s[1], s[2], s[3], s[4], s[5])
	d := hdr.DAddr
	r2 := fmt.Sprintf("Ethernet Destination: %02x:%02x:%02x:%02x:%02x:%02x\n", d[0], d[1], d[2], d[3], d[4], d[5])
	return r0 + r1 + r2
}

// L3 header from DPDK: lib/librte_net/rte_ip.h
type IPv4Hdr struct {
	VersionIhl     uint8  // version and header length
	TypeOfService  uint8  // type of service
	TotalLength    uint16 // length of packet
	PacketID       uint16 // packet ID
	FragmentOffset uint16 // fragmentation offset
	TimeToLive     uint8  // time to live
	NextProtoID    uint8  // protocol ID
	HdrChecksum    uint16 // header checksum
	SrcAddr        uint32 // source address
	DstAddr        uint32 // destination address
}

func (hdr *IPv4Hdr) String() string {
	r0 := "    L3 protocol: IPv4\n"
	s := hdr.SrcAddr
	r1 := fmt.Sprintln("    IPv4 Source:", byte(s), ":", byte(s>>8), ":", byte(s>>16), ":", byte(s>>24))
	d := hdr.DstAddr
	r2 := fmt.Sprintln("    IPv4 Destination:", byte(d), ":", byte(d>>8), ":", byte(d>>16), ":", byte(d>>24))
	return r0 + r1 + r2
}

// L3 header from DPDK: lib/librte_net/rte_ip.h
type IPv6Hdr struct {
	VtcFlow    uint32             // IP version, traffic class & flow label
	PayloadLen uint16             // IP packet length - includes sizeof(ip_header)
	Proto      uint8              // Protocol, next header
	HopLimits  uint8              // Hop limits
	SrcAddr    [IPv6AddrLen]uint8 // IP address of source host
	DstAddr    [IPv6AddrLen]uint8 // IP address of destination host(s)
}

func (hdr *IPv6Hdr) String() string {
	r0 := "    L3 protocol: IPv6\n"
	s := hdr.SrcAddr
	r1 := fmt.Sprintf("    IPv6 Source: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15])
	d := hdr.DstAddr
	r2 := fmt.Sprintf("    IPv6 Destination %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15])
	return r0 + r1 + r2
}

// L4 header from DPDK: lib/librte_net/rte_tcp.h
type TCPHdr struct {
	SrcPort  uint16 // TCP source port
	DstPort  uint16 // TCP destination port
	SentSeq  uint32 // TX data sequence number
	RecvAck  uint32 // RX data acknowledgement sequence number
	DataOff  uint8  // Data offset
	TCPFlags uint8  // TCP flags
	RxWin    uint16 // RX flow control window
	Cksum    uint16 // TCP checksum
	TCPUrp   uint16 // TCP urgent pointer, if any
}

func (hdr *TCPHdr) String() string {
	r0 := "        L4 protocol: TCP\n"
	r1 := fmt.Sprintf("        L4 Source: %d\n", SwapBytesUint16(hdr.SrcPort))
	r2 := fmt.Sprintf("        L4 Destination: %d\n", SwapBytesUint16(hdr.DstPort))
	return r0 + r1 + r2
}

// L4 header from DPDK: lib/librte_net/rte_udp.h
type UDPHdr struct {
	SrcPort    uint16 // UDP source port
	DstPort    uint16 // UDP destination port
	DgramLen   uint16 // UDP datagram length
	DgramCksum uint16 // UDP datagram checksum
}

func (hdr *UDPHdr) String() string {
	r0 := "        L4 protocol: UDP\n"
	r1 := fmt.Sprintf("        L4 Source: %d\n", SwapBytesUint16(hdr.SrcPort))
	r2 := fmt.Sprintf("        L4 Destination: %d\n", SwapBytesUint16(hdr.DstPort))
	return r0 + r1 + r2
}

// Packet is a set of pointers in YANFF library. Each pointer points to one of five headers:
// Mac, IPv4, IPv6, TCP and UDP plus raw pointer.
//
// Empty packet means that only raw pointer is not nil: it points to beginning of packet data
// – raw bits. User should extract packet data somehow.
//
// Parsing means to fill required header pointers with corresponding headers. For example,
// after user fills IPv4 pointer to right place inside packet he can use its fields like
// packet.IPv4.SrcAddr or packet.IPv4.DstAddr.
type Packet struct {
	Ether    *EtherHdr      // Pointer to L2 header in mbuf (must be nil before parsing)
	IPv4     *IPv4Hdr       // Pointer to L3 header in mbuf (must be nil before parsing)
	IPv6     *IPv6Hdr       // Pointer to L3 header in mbuf (must be nil before parsing)
	TCP      *TCPHdr        // Pointer to L4 header in mbuf (must be nil before parsing)
	UDP      *UDPHdr        // Pointer to L4 header in mbuf (must be nil before parsing)
	Data     unsafe.Pointer // Pointer to the packet payload data (invalid before parsing)
	Unparsed uintptr        // Pointer whole packet data in mbuf (must be non-nil because it is the only public whole element)

	CMbuf *low.Mbuf // Private pointer to mbuf. Users shouldn't know anything about mbuf
}

// ParseEther set pointer to Ethernet header in packet.
func (packet *Packet) ParseEther() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
}

// ParseEtherData set pointer to Ethernet header and Data in packet.
// Data is considered to be everything after Ethernet header.
func (packet *Packet) ParseEtherData() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.Data = unsafe.Pointer(packet.Unparsed + EtherLen)
}

// ParseEtherIPv4 set pointer to Ethernet and IPv4 headers in packet.
func (packet *Packet) ParseEtherIPv4() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
}

// ParseEtherIPv4Data set pointer to Ethernet, IPv4 headers and Data in packet.
// Data is considered to be everything after these headers.
func (packet *Packet) ParseEtherIPv4Data() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.Data = unsafe.Pointer(packet.Unparsed + EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2))
}

// ParseEtherIPv6 set pointer to Ethernet, IPv6 headers in packet.
func (packet *Packet) ParseEtherIPv6() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
}

// ParseEtherIPv6Data set pointer to Ethernet, IPv6 headers and Data in packet.
// Data is considered to be everything after these headers.
func (packet *Packet) ParseEtherIPv6Data() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.Data = unsafe.Pointer(packet.Unparsed + EtherLen + IPv6Len)
}

// ParseEtherIPv4TCP set pointer to Ethernet, IPv4, TCP headers in packet.
func (packet *Packet) ParseEtherIPv4TCP() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
}

// ParseEtherIPv4TCPData set pointer to Ethernet, IPv4, TCP headers and Data in packet.
// Data is considered to be everything after these headers.
func (packet *Packet) ParseEtherIPv4TCPData() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
	dataOffset := EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2) + uintptr((packet.TCP.DataOff&0xf0)>>2)
	packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
}

// ParseEtherIPv4UDP set pointer to Ethernet, IPv4, UDP headers in packet.
func (packet *Packet) ParseEtherIPv4UDP() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
}

// ParseEtherIPv4UDPData set pointer to Ethernet, IPv4, UDP headers and Data in packet.
// Data is considered to be everything after these headers.
func (packet *Packet) ParseEtherIPv4UDPData() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
	dataOffset := EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2) + UDPLen
	packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
}

// ParseEtherIPv6TCP set pointer to Ethernet, IPv6, TCP headers in packet.
func (packet *Packet) ParseEtherIPv6TCP() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	if packet.IPv6.Proto == TCPNumber {
		packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + EtherIPv6Len))
	}
}

// ParseEtherIPv6TCPData set pointer to Ethernet, IPv6, TCP headers and Data in packet.
// Data is considered to be everything after these headers.
func (packet *Packet) ParseEtherIPv6TCPData() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	if packet.IPv6.Proto == TCPNumber {
		packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + EtherIPv6Len))
		dataOffset := EtherLen + IPv6Len + uintptr((packet.TCP.DataOff&0xf0)>>2)
		packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
	}
}

// ParseEtherIPv6UDP set pointer to Ethernet, IPv6, UDP headers in packet.
func (packet *Packet) ParseEtherIPv6UDP() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	if packet.IPv6.Proto == UDPNumber {
		packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + EtherIPv6Len))
	}
}

// ParseEtherIPv6UDPData set pointer to Ethernet, IPv6, UDP headers and Data in packet.
// Data is considered to be everything after these headers.
func (packet *Packet) ParseEtherIPv6UDPData() {
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	if packet.IPv6.Proto == UDPNumber {
		packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + EtherIPv6Len))
		dataOffset := EtherLen + IPv6Len + UDPLen
		packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
	}
}

// ParseIPv4 set pointer to IPv4 header in packet.
func (packet *Packet) ParseIPv4() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
}

// ParseIPv4Data set pointer to IPv4 header and Data in packet.
// Data is considered to be everything after the header.
func (packet *Packet) ParseIPv4Data() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.Data = unsafe.Pointer(packet.Unparsed + EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2))
}

// ParseIPv6 set pointer to IPv6 header in packet.
func (packet *Packet) ParseIPv6() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
}

// ParseIPv6Data set pointer to IPv6 header and Data in packet.
// Data is considered to be everything after the header.
func (packet *Packet) ParseIPv6Data() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.Data = unsafe.Pointer(packet.Unparsed + EtherLen + IPv6Len)
}

// ParseIPv4TCP set pointers to IPv4, TCP headers in packet.
func (packet *Packet) ParseIPv4TCP() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
}

// ParseIPv4TCPData set pointers to IPv4, TCP headers and Data in packet.
// Data is considered to be everything after the headers.
func (packet *Packet) ParseIPv4TCPData() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
	dataOffset := EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2) + uintptr((packet.TCP.DataOff&0xf0)>>2)
	packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
}

// ParseIPv4UDP set pointers to IPv4, UDP headers in packet.
func (packet *Packet) ParseIPv4UDP() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
}

// ParseIPv4UDP set pointers to IPv4, UDP headers in packet.
// Data is considered to be everything after the headers.
func (packet *Packet) ParseIPv4UDPData() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
	dataOffset := EtherLen + uintptr((packet.IPv4.VersionIhl&0x0f)<<2) + UDPLen
	packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
}

// ParseIPv6TCP will parse L4 level protocol only if there are no extended headers
// after IPv6 fix header. However fix IPv6 part will be parsed anyway.
func (packet *Packet) ParseIPv6TCP() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	if packet.IPv6.Proto == TCPNumber {
		packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + EtherIPv6Len))
	}
}

// ParseIPv6TCPData will parse L4 level protocol and Data only if there are no extended headers
// after IPv6 fix header. However fix IPv6 part will be parsed anyway.
func (packet *Packet) ParseIPv6TCPData() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	if packet.IPv6.Proto == TCPNumber {
		packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + EtherIPv6Len))
		dataOffset := EtherLen + IPv6Len + int((packet.TCP.DataOff&0xf0)>>2)
		packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
	}
}

// ParseIPv6UDP will parse L4 level protocol only if there are no extended headers
// after IPv6 fix header. However fix IPv6 part will be parsed anyway.
func (packet *Packet) ParseIPv6UDP() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	if packet.IPv6.Proto == UDPNumber {
		packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + EtherIPv6Len))
	}
}

// ParseIPv6UDP will parse L4 level protocol and Data only if there are no extended headers
// after IPv6 fix header. However fix IPv6 part will be parsed anyway.
func (packet *Packet) ParseIPv6UDPData() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + EtherLen))
	if packet.IPv6.Proto == UDPNumber {
		packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + EtherIPv6Len))
		dataOffset := EtherLen + IPv6Len + UDPLen
		packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
	}
}

// ParseTCP takes offset to beginning of TCP header as parameter. Offset is needed, because
// length of L3 level protocol can be different, so parsing L4 without L3 is applicable
// only with manual offset. Usually these offset will be 14 + 20 for IPv4 and 14 + 40 for IPv6.
func (packet *Packet) ParseTCP(offset uint8) {
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + uintptr(offset)))
}

func (packet *Packet) ParseTCPData(offset uint8) {
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + uintptr(offset)))
	packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(offset) + uintptr(packet.TCP.DataOff&0xf0)>>2)
}

// ParseUDP takes offset to beginning of UDP header as parameter. Offset is needed, because
// length of L3 level protocol can be different, so parsing L4 without L3 is applicable
// only with manual offset. Usually these offset will be 14 + 20 for IPv4 and 14 + 40 for IPv6.
func (packet *Packet) ParseUDP(offset uint8) {
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + uintptr(offset)))
}

func (packet *Packet) ParseUDPData(offset uint8) {
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + uintptr(offset)))
	packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(offset) + UDPLen)
}

// ParseL2 fills L2 layer pointer unconditionally because it is assumed that
// NIC supports only Ethernet packets. Returns length of Ethernet header.
func (packet *Packet) ParseL2() int {
	// Our cards can receive only ethernet packets, so no condition here.
	packet.Ether = (*EtherHdr)(unsafe.Pointer(packet.Unparsed))
	return EtherLen
}

// ParseL3 fills L2 and then L3 layers pointers: either IPv4 or IPv6.
// Returns length of Ethernet plus IP headers and L4 layer protocol ID.
// Return (-1, 0) if protocols are neither IPv4 nor IPv6 or is IPv6 has
// additional components. Such packets aren't supported now.
func (packet *Packet) ParseL3() (int, uint8) {
	L := packet.ParseL2()
	if L == -1 {
		return -1, 0
	}
	// TODO here and in other conditions we should investigate possibility of using packetType
	// from mbuf. It is hardware optimization of some network cards.
	if packet.Ether.EtherType == SwapBytesUint16(IPV4Number) {
		packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + uintptr(L)))
		return L + int((packet.IPv4.VersionIhl&0x0f)<<2), packet.IPv4.NextProtoID
	}
	if packet.Ether.EtherType == SwapBytesUint16(IPV6Number) {
		packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + uintptr(L)))
		if packet.IPv6.Proto == TCPNumber || packet.IPv6.Proto == UDPNumber {
			return L + IPv6Len, packet.IPv6.Proto
		}
	}
	return -1, 0
}

// ParseL3 fills L2 and then L3 layers pointers: either IPv4 or IPv6, and also fills Data pointer.
// Returns length of Ethernet plus IP headers and L4 layer protocol ID.
// Return (-1, 0) if protocols are neither IPv4 nor IPv6 or is IPv6 has
// additional components. Such packets aren't supported now.
func (packet *Packet) ParseL3Data() (int, uint8) {
	L := packet.ParseL2()
	if L == -1 {
		return -1, 0
	}
	if packet.Ether.EtherType == SwapBytesUint16(IPV4Number) {
		packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.Unparsed + uintptr(L)))
		dataOffset := L + int((packet.IPv4.VersionIhl&0x0f)<<2)
		packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
		return dataOffset, packet.IPv4.NextProtoID
	}
	if packet.Ether.EtherType == SwapBytesUint16(IPV6Number) {
		packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.Unparsed + uintptr(L)))
		if packet.IPv6.Proto == TCPNumber || packet.IPv6.Proto == UDPNumber {
			dataOffset := L + IPv6Len
			packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
			return dataOffset, packet.IPv6.Proto
		}
	}
	return -1, 0
}

// ParseL4 fills L2, L3 and L4 layers pointers: either TCP or UDP.
// Returns summary length of all these headers. Returns -1 if L4 is
// neither TCP nor UDP or previous protocols have problems.
func (packet *Packet) ParseL4() int {
	L, L4Type := packet.ParseL3()
	if L == -1 {
		return -1
	}
	if L4Type == TCPNumber {
		packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + uintptr(L)))
		return L + int((packet.TCP.DataOff&0xf0)>>2)
	}
	if L4Type == UDPNumber {
		packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + uintptr(L)))
		return L + UDPLen
	}
	return -1
}

// ParseL4Data fills L2, L3 and L4 layers pointers: either TCP or UDP,
// and also fills Data pointer. Returns summary length of all these headers.
// Returns -1 if L4 is neither TCP nor UDP or previous protocols have problems.
func (packet *Packet) ParseL4Data() int {
	L, L4Type := packet.ParseL3()
	if L == -1 {
		return -1
	}
	if L4Type == TCPNumber {
		packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + uintptr(L)))
		dataOffset := L + int((packet.TCP.DataOff&0xf0)>>2)
		packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
		return dataOffset
	}
	if L4Type == UDPNumber {
		packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + uintptr(L)))
		dataOffset := L + UDPLen
		packet.Data = unsafe.Pointer(packet.Unparsed + uintptr(dataOffset))
		return dataOffset
	}
	return -1
}

// ExtractPacket, ExtractPacketAddr, ToPacket extract packet structure from mbuf
// TODO These should be unexported method. However now it is exported to be used in package flow.
func ExtractPacketAddr(IN uintptr) uintptr {
	return IN + mbufStructSize
}

func ToPacket(IN uintptr) *Packet {
	return (*Packet)(unsafe.Pointer(IN))
}

func ExtractPacket(IN uintptr) *Packet {
	return ToPacket(ExtractPacketAddr(IN))
}

// Create vector of packets by calling ExtractPacket function
// TODO This should be unexported method. However now it is exported to be used in package flow.
func ExtractPackets(packet []*Packet, IN []uintptr, n uint) {
	for i := uint(0); i < n; i++ {
		packet[i] = ExtractPacket(IN[i])
	}
}

// PacketFromByte function gets non-initialized packet and slice of bytes of any size.
// Initializes input packet and fills it with these bytes.
func PacketFromByte(packet *Packet, data []byte) {
	low.AppendMbuf(packet.CMbuf, uint(len(data)))
	low.WriteDataToMbuf(packet.CMbuf, data)
}

// All following functions set Data pointer because it is assumed that user
// need to generate real packets with some information

// InitEmptyEtherPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointer to Ethernet header.
func InitEmptyEtherPacket(packet *Packet, plSize uint) {
	bufSize := plSize + EtherLen
	low.AppendMbuf(packet.CMbuf, bufSize)

	packet.ParseEtherData()
}

// InitEmptyEtherIPv4Packet initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet and IPv4 headers.
func InitEmptyEtherIPv4Packet(packet *Packet, plSize uint) {
	// TODO After mandatory fields, IPv4 header optionally may have options of variable length
	// Now pre-allocate space only for mandatory fields
	bufSize := plSize + EtherLen + IPv4MinLen
	low.AppendMbuf(packet.CMbuf, bufSize)

	// Set pointers to required headers. Filling headers is left for user
	packet.ParseEtherIPv4()

	// After packet is parsed, we can write to packet struct known protocol types
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.Unparsed + EtherLen + IPv4MinLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.IPv4.VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.IPv4.TotalLength = SwapBytesUint16(uint16(IPv4MinLen + plSize))
}

// InitEmptyEtherIPv6Packet initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet and IPv6 headers.
func InitEmptyEtherIPv6Packet(packet *Packet, plSize uint) {
	bufSize := plSize + EtherLen + IPv6Len
	low.AppendMbuf(packet.CMbuf, bufSize)

	packet.ParseEtherIPv6Data()
	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.IPv6.PayloadLen = SwapBytesUint16(uint16(plSize))
}

// InitEmptyEtherIPv4TCPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv4 and TCP headers. This function supposes that IPv4 and TCP
// headers have minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyEtherIPv4TCPPacket(packet *Packet, plSize uint) {
	// Now user cannot set explicitly optional fields, so len of header is supposed to be equal to TCPMinLen
	// TODO support variable header length (ask header length from user)
	bufSize := plSize + EtherLen + IPv4MinLen + TCPMinLen
	low.AppendMbuf(packet.CMbuf, bufSize)

	// Set pointer to required headers. Filling headers is left for user
	packet.ParseEtherIPv4()
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + IPv4MinLen))
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.Unparsed + EtherLen + IPv4MinLen + TCPMinLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.IPv4.NextProtoID = TCPNumber
	packet.IPv4.VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.IPv4.TotalLength = SwapBytesUint16(uint16(IPv4MinLen + TCPMinLen + plSize))
	packet.TCP.DataOff = packet.TCP.DataOff | 0x50
}

// InitEmptyEtherIPv4UDPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv4 and UDP headers. This function supposes that IPv4
// header has minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyEtherIPv4UDPPacket(packet *Packet, plSize uint) {
	bufSize := plSize + EtherLen + IPv4MinLen + UDPLen
	low.AppendMbuf(packet.CMbuf, bufSize)

	packet.ParseEtherIPv4()
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + IPv4MinLen))
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.Unparsed + EtherLen + IPv4MinLen + UDPLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.IPv4.NextProtoID = UDPNumber
	packet.IPv4.VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.IPv4.TotalLength = SwapBytesUint16(uint16(IPv4MinLen + UDPLen + plSize))
	packet.UDP.DgramLen = uint16(UDPLen + plSize)
}

// InitEmptyEtherIPv6TCPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv6 and TCP headers. This function supposes that IPv6 and TCP
// headers have minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyEtherIPv6TCPPacket(packet *Packet, plSize uint) {
	// TODO support variable header length (ask header length from user)
	bufSize := plSize + EtherLen + IPv6Len + TCPMinLen
	low.AppendMbuf(packet.CMbuf, bufSize)

	packet.ParseEtherIPv6()
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + IPv6Len))
	packet.Data = unsafe.Pointer(packet.Unparsed + EtherLen + IPv4MinLen + TCPMinLen)

	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.IPv6.Proto = TCPNumber
	packet.IPv6.PayloadLen = SwapBytesUint16(uint16(TCPMinLen + plSize))
}

// InitEmptyEtherIPv6UDPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv6 and UDP headers. This function supposes that IPv6
// header has minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyEtherIPv6UDPPacket(packet *Packet, plSize uint) {
	bufSize := plSize + EtherLen + IPv6Len + UDPLen
	low.AppendMbuf(packet.CMbuf, bufSize)

	packet.ParseEtherIPv6()
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.Unparsed + EtherLen + IPv6Len))
	packet.Data = unsafe.Pointer(packet.Unparsed + EtherLen + IPv6Len + UDPLen)

	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.IPv6.Proto = UDPNumber
	packet.IPv6.PayloadLen = SwapBytesUint16(uint16(UDPLen + plSize))
	packet.UDP.DgramLen = uint16(UDPLen + plSize)
}

// Swapping uint16 in Little Endian and Big Endian
func SwapBytesUint16(x uint16) uint16 {
	return x<<8 | x>>8
}

// Swapping uint32 in Little Endian and Big Endian
func SwapBytesUint32(x uint32) uint32 {
	return ((x & 0x000000ff) << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | ((x & 0xff000000) >> 24)
}

// GetRawPacketBytes returns all bytes from this packet. Not zero-copy.
func (packet *Packet) GetRawPacketBytes() []byte {
	return low.GetRawPacketBytesMbuf(packet.CMbuf)
}

// GetPacketLen returns length of this packet
func (packet *Packet) GetPacketLen() uint {
	return low.GetDataLenMbuf(packet.CMbuf)
}

// EncapsulateHead adds bytes to packet. start - number of beginning byte, length - number of
// added bytes. This function should be used to add bytes to the first half
// of packet. Return false if error.
func (packet *Packet) EncapsulateHead(start uint, length uint) bool {
	if low.PrependMbuf(packet.CMbuf, length) == false {
		return false
	}
	packet.Unparsed -= uintptr(length)
	for i := uint(0); i < start; i++ {
		*(*uint8)(unsafe.Pointer(packet.Unparsed + uintptr(i))) = *(*uint8)(unsafe.Pointer(packet.Unparsed + uintptr(i+length)))
	}
	return true
}

// EncapsulateTail adds bytes to packet. start - number of beginning byte, length - number of
// added bytes. This function should be used to add bytes to the second half
// of packet. Return false if error.
func (packet *Packet) EncapsulateTail(start uint, length uint) bool {
	if low.AppendMbuf(packet.CMbuf, length) == false {
		return false
	}
	packetLength := packet.GetPacketLen()
	for i := packetLength - 1; int(i) >= int(start+length); i-- {
		*(*uint8)(unsafe.Pointer(packet.Unparsed + uintptr(i))) = *(*uint8)(unsafe.Pointer(packet.Unparsed + uintptr(i-length)))
	}
	return true
}

// DecapsulateHead removes bytes from packet. start - number of beginning byte, length - number of
// removed bytes. This function should be used to remove bytes from the first half
// of packet. Return false if error.
func (packet *Packet) DecapsulateHead(start uint, length uint) bool {
	if low.AdjMbuf(packet.CMbuf, length) == false {
		return false
	}
	for i := int(start - 1); i >= 0; i-- {
		*(*uint8)(unsafe.Pointer(packet.Unparsed + uintptr(i+int(length)))) = *(*uint8)(unsafe.Pointer(packet.Unparsed + uintptr(i)))
	}
	packet.Unparsed += uintptr(length)
	return true
}

// DecapsulateTail removes bytes from packet. start - number of beginning byte, length - number of
// removed bytes. This function should be used to remove bytes from the second half
// of packet. Return false if error.
func (packet *Packet) DecapsulateTail(start uint, length uint) bool {
	packetLength := packet.GetPacketLen() // This won't be changed by next operation
	if low.TrimMbuf(packet.CMbuf, length) == false {
		return false
	}
	for i := start; i < packetLength; i++ {
		*(*uint8)(unsafe.Pointer(packet.Unparsed + uintptr(i))) = *(*uint8)(unsafe.Pointer(packet.Unparsed + uintptr(i+length)))
	}
	return true
}

// PacketBytesChange changes packet bytes from start byte to given bytes.
// Return false if error.
func (packet *Packet) PacketBytesChange(start uint, bytes []byte) bool {
	length := uint(len(bytes))
	if start+length > packet.GetPacketLen() {
		return false
	}
	for i := uint(0); i < length; i++ {
		*(*byte)(unsafe.Pointer(packet.Unparsed + uintptr(start+i))) = bytes[i]
	}
	return true
}
