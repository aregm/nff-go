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
	. "github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
	"unsafe"
)

var mbufStructSize uintptr
var hwtxchecksum bool

func init() {
	var t1 low.Mbuf
	mbufStructSize = unsafe.Sizeof(t1)
	var t2 Packet
	packetStructSize := unsafe.Sizeof(t2)
	low.SetPacketStructSize(int(packetStructSize))
}

// TODO Add function to write user data after headers and set "data" field

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
	TCPFlags TCPFlags // TCP flags
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

type ICMPHdr struct {
	Type       uint8  // ICMP message type
	Code       uint8  // ICMP message code
	Cksum      uint16 // ICMP checksum
	Identifier uint16 // ICMP message identifier in some messages
	SeqNum     uint16 // ICMP message sequence number in some messages
}

func (hdr *ICMPHdr) String() string {
	r0 := "        L4 protocol: ICMP\n"
	r1 := fmt.Sprintf("        ICMP Type: %d\n", hdr.Type)
	r2 := fmt.Sprintf("        ICMP Code: %d\n", hdr.Code)
	r3 := fmt.Sprintf("        ICMP Cksum: %d\n", SwapBytesUint16(hdr.Cksum))
	r4 := fmt.Sprintf("        ICMP Identifier: %d\n", SwapBytesUint16(hdr.Identifier))
	r5 := fmt.Sprintf("        ICMP SeqNum: %d\n", SwapBytesUint16(hdr.SeqNum))
	return r0 + r1 + r2 + r3 + r4 + r5
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
	IPv4 *IPv4Hdr       // Pointer to L3 header in mbuf (must be nil before parsing)
	IPv6 *IPv6Hdr       // Pointer to L3 header in mbuf (must be nil before parsing)
	TCP  *TCPHdr        // Pointer to L4 header in mbuf (must be nil before parsing)
	UDP  *UDPHdr        // Pointer to L4 header in mbuf (must be nil before parsing)
	ICMP *ICMPHdr       // Pointer to L4 header in mbuf (must be nil before parsing)
	Data unsafe.Pointer // Pointer to the packet payload data (invalid before parsing)

	// Last two fields of this structure is filled during InitMbuf macros inside low.c file
	// Need to change low.c for all changes in these fields or adding/removing fields before them.
	Ether *EtherHdr // Pointer to L2 header in mbuf. It is always parsed and point begining of packet.
	CMbuf *low.Mbuf // Private pointer to mbuf. Users shouldn't know anything about mbuf
}

func (packet *Packet) unparsed() uintptr {
	return uintptr(unsafe.Pointer(packet.Ether)) + EtherLen
}

// Start function return pointer to first byte of packet
// Which is the same as first byte of ethernet protocol header
func (packet *Packet) Start() uintptr {
	return uintptr(unsafe.Pointer(packet.Ether))
}

// ParseData set pointer to Data in packet.
// Data is considered to be everything after Ethernet header.
func (packet *Packet) ParseData() {
	packet.Data = unsafe.Pointer(packet.unparsed())
}

// ParseIPv4 set pointer to IPv4 header in packet.
func (packet *Packet) ParseIPv4() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.unparsed()))
}

// ParseIPv4Data set pointer to IPv4 header and Data in packet.
// Data is considered to be everything after the header.
func (packet *Packet) ParseIPv4Data() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.unparsed()))
	packet.Data = unsafe.Pointer(packet.unparsed() + uintptr((packet.IPv4.VersionIhl&0x0f)<<2))
}

// ParseIPv6 set pointer to IPv6 header in packet.
func (packet *Packet) ParseIPv6() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.unparsed()))
}

// ParseIPv6Data set pointer to IPv6 header and Data in packet.
// Data is considered to be everything after the header.
func (packet *Packet) ParseIPv6Data() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.unparsed()))
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv6Len)
}

// ParseIPv4TCP set pointers to IPv4, TCP headers in packet.
func (packet *Packet) ParseIPv4TCP() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.unparsed()))
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.unparsed() + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
}

// ParseIPv4TCPData set pointers to IPv4, TCP headers and Data in packet.
// Data is considered to be everything after the headers.
func (packet *Packet) ParseIPv4TCPData() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.unparsed()))
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.unparsed() + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
	packet.Data = unsafe.Pointer(packet.unparsed() + uintptr((packet.IPv4.VersionIhl&0x0f)<<2) + uintptr((packet.TCP.DataOff&0xf0)>>2))
}

// ParseIPv4UDP set pointers to IPv4, UDP headers in packet.
func (packet *Packet) ParseIPv4UDP() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.unparsed()))
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.unparsed() + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
}

// ParseIPv4UDP set pointers to IPv4, UDP headers in packet.
// Data is considered to be everything after the headers.
func (packet *Packet) ParseIPv4UDPData() {
	packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.unparsed()))
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.unparsed() + uintptr((packet.IPv4.VersionIhl&0x0f)<<2)))
	packet.Data = unsafe.Pointer(packet.unparsed() + uintptr((packet.IPv4.VersionIhl&0x0f)<<2) + UDPLen)
}

// ParseIPv6TCP will parse L4 level protocol only if there are no extended headers
// after IPv6 fix header. However fix IPv6 part will be parsed anyway.
func (packet *Packet) ParseIPv6TCP() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.unparsed()))
	if packet.IPv6.Proto == TCPNumber {
		packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.unparsed() + IPv6Len))
	}
}

// ParseIPv6TCPData will parse L4 level protocol and Data only if there are no extended headers
// after IPv6 fix header. However fix IPv6 part will be parsed anyway.
func (packet *Packet) ParseIPv6TCPData() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.unparsed()))
	if packet.IPv6.Proto == TCPNumber {
		packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.unparsed() + IPv6Len))
		packet.Data = unsafe.Pointer(packet.unparsed() + IPv6Len + uintptr((packet.TCP.DataOff&0xf0)>>2))
	}
}

// ParseIPv6UDP will parse L4 level protocol only if there are no extended headers
// after IPv6 fix header. However fix IPv6 part will be parsed anyway.
func (packet *Packet) ParseIPv6UDP() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.unparsed()))
	if packet.IPv6.Proto == UDPNumber {
		packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.unparsed() + IPv6Len))
	}
}

// ParseIPv6UDP will parse L4 level protocol and Data only if there are no extended headers
// after IPv6 fix header. However fix IPv6 part will be parsed anyway.
func (packet *Packet) ParseIPv6UDPData() {
	packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.unparsed()))
	if packet.IPv6.Proto == UDPNumber {
		packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.unparsed() + IPv6Len))
		packet.Data = unsafe.Pointer(packet.unparsed() + IPv6Len + UDPLen)
	}
}

// ParseTCP takes offset to beginning of TCP header as parameter. Offset is needed, because
// length of L3 level protocol can be different, so parsing L4 without L3 is applicable
// only with manual offset. Usually these offset will be 14 + 20 for IPv4 and 14 + 40 for IPv6.
func (packet *Packet) ParseTCP(offset uint8) {
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(offset)))
}

func (packet *Packet) ParseTCPData(offset uint8) {
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(offset)))
	packet.Data = unsafe.Pointer(packet.unparsed() + uintptr(offset) + uintptr(packet.TCP.DataOff&0xf0)>>2)
}

// ParseUDP takes offset to beginning of UDP header as parameter. Offset is needed, because
// length of L3 level protocol can be different, so parsing L4 without L3 is applicable
// only with manual offset. Usually these offset will be 14 + 20 for IPv4 and 14 + 40 for IPv6.
func (packet *Packet) ParseUDP(offset uint8) {
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(offset)))
}

func (packet *Packet) ParseICMP(offset uint8) {
	packet.ICMP = (*ICMPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(offset)))
}

func (packet *Packet) ParseUDPData(offset uint8) {
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(offset)))
	packet.Data = unsafe.Pointer(packet.unparsed() + uintptr(offset) + UDPLen)
}

// ParseL3 fills L3 layer pointers: either IPv4 or IPv6.
// Returns length of IP headers and L4 layer protocol ID.
// Return (-1, 0) if protocols are neither IPv4 nor IPv6 or if IPv6 has
// additional components. Such packets aren't supported now.
func (packet *Packet) ParseL3() (int, uint8) {
	// TODO here and in other conditions we should investigate possibility of using packetType
	// from mbuf. It is hardware optimization of some network cards.
	if packet.Ether.EtherType == SwapBytesUint16(IPV4Number) {
		packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.unparsed()))
		return int((packet.IPv4.VersionIhl & 0x0f) << 2), packet.IPv4.NextProtoID
	}
	if packet.Ether.EtherType == SwapBytesUint16(IPV6Number) {
		packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.unparsed()))
		if packet.IPv6.Proto == TCPNumber || packet.IPv6.Proto == UDPNumber {
			return IPv6Len, packet.IPv6.Proto
		}
	}
	return -1, 0
}

// ParseL3 fills L3 layer pointers: either IPv4 or IPv6, and also fills Data pointer.
// Returns length of IP headers and L4 layer protocol ID.
// Return (-1, 0) if protocols are neither IPv4 nor IPv6 or if IPv6 has
// additional components. Such packets aren't supported now.
func (packet *Packet) ParseL3Data() (int, uint8) {
	if packet.Ether.EtherType == SwapBytesUint16(IPV4Number) {
		packet.IPv4 = (*IPv4Hdr)(unsafe.Pointer(packet.unparsed()))
		dataOffset := int((packet.IPv4.VersionIhl & 0x0f) << 2)
		packet.Data = unsafe.Pointer(packet.unparsed() + uintptr(dataOffset))
		return dataOffset, packet.IPv4.NextProtoID
	}
	if packet.Ether.EtherType == SwapBytesUint16(IPV6Number) {
		packet.IPv6 = (*IPv6Hdr)(unsafe.Pointer(packet.unparsed()))
		if packet.IPv6.Proto == TCPNumber || packet.IPv6.Proto == UDPNumber {
			dataOffset := IPv6Len
			packet.Data = unsafe.Pointer(packet.unparsed() + uintptr(dataOffset))
			return dataOffset, packet.IPv6.Proto
		}
	}
	return -1, 0
}

// ParseL4 fills L3 and L4 layers pointers: TCP, UDP or ICMP.
// Returns summary length of all L3 + L4 headers. Returns -1 if L4 is
// neither TCP nor UDP nor ICMP or previous protocols have problems.
func (packet *Packet) ParseL4() int {
	L, L4Type := packet.ParseL3()
	if L == -1 {
		return -1
	}
	if L4Type == TCPNumber {
		packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(L)))
		return L + int((packet.TCP.DataOff&0xf0)>>2)
	}
	if L4Type == UDPNumber {
		packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(L)))
		return L + UDPLen
	}
	if L4Type == ICMPNumber {
		packet.ICMP = (*ICMPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(L)))
		return L + ICMPLen
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
		packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(L)))
		dataOffset := L + int((packet.TCP.DataOff&0xf0)>>2)
		packet.Data = unsafe.Pointer(packet.unparsed() + uintptr(dataOffset))
		return dataOffset
	}
	if L4Type == UDPNumber {
		packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(L)))
		dataOffset := L + UDPLen
		packet.Data = unsafe.Pointer(packet.unparsed() + uintptr(dataOffset))
		return dataOffset
	}
	if L4Type == ICMPNumber {
		packet.ICMP = (*ICMPHdr)(unsafe.Pointer(packet.unparsed() + uintptr(L)))
		dataOffset := L + ICMPLen
		packet.Data = unsafe.Pointer(packet.unparsed() + uintptr(dataOffset))
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

// Another function which should not be exported but it is used in flow.
func SetHWTXChecksumFlag(flag bool) {
	hwtxchecksum = flag
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
func PacketFromByte(packet *Packet, data []byte) bool {
	if low.AppendMbuf(packet.CMbuf, uint(len(data))) == false {
		LogWarning(Debug, "PacketFromByte: Cannot append mbuf")
		return false
	}
	low.WriteDataToMbuf(packet.CMbuf, data)
	return true
}

// All following functions set Data pointer because it is assumed that user
// need to generate real packets with some information

// InitEmptyPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointer to Ethernet header.
func InitEmptyPacket(packet *Packet, plSize uint) bool {
	bufSize := plSize + EtherLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyPacket: Cannot append mbuf")
		return false
	}
	packet.Data = unsafe.Pointer(packet.unparsed())
	return true
}

// InitEmptyIPv4Packet initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet and IPv4 headers.
func InitEmptyIPv4Packet(packet *Packet, plSize uint) bool {
	// TODO After mandatory fields, IPv4 header optionally may have options of variable length
	// Now pre-allocate space only for mandatory fields
	bufSize := plSize + EtherLen + IPv4MinLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv4Packet: Cannot append mbuf")
		return false
	}
	// Set pointers to required headers. Filling headers is left for user
	packet.ParseIPv4()

	// After packet is parsed, we can write to packet struct known protocol types
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv4MinLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.IPv4.VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.IPv4.TotalLength = SwapBytesUint16(uint16(IPv4MinLen + plSize))

	if hwtxchecksum {
		packet.IPv4.HdrChecksum = 0
		low.SetTXIPv4OLFlags(packet.CMbuf, EtherLen, IPv4MinLen)
	}
	return true
}

// InitEmptyIPv6Packet initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet and IPv6 headers.
func InitEmptyIPv6Packet(packet *Packet, plSize uint) bool {
	bufSize := plSize + EtherLen + IPv6Len
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv6Packet: Cannot append mbuf")
		return false
	}
	packet.ParseIPv6Data()
	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.IPv6.PayloadLen = SwapBytesUint16(uint16(plSize))
	packet.IPv6.VtcFlow = SwapBytesUint32(0x60 << 24) // IP version
	return true
}

// InitEmptyIPv4TCPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv4 and TCP headers. This function supposes that IPv4 and TCP
// headers have minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyIPv4TCPPacket(packet *Packet, plSize uint) bool {
	// Now user cannot set explicitly optional fields, so len of header is supposed to be equal to TCPMinLen
	// TODO support variable header length (ask header length from user)
	bufSize := plSize + EtherLen + IPv4MinLen + TCPMinLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyPacket: Cannot append mbuf")
		return false
	}
	// Set pointer to required headers. Filling headers is left for user
	packet.ParseIPv4()
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.unparsed() + IPv4MinLen))
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv4MinLen + TCPMinLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.IPv4.NextProtoID = TCPNumber
	packet.IPv4.VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.IPv4.TotalLength = SwapBytesUint16(uint16(IPv4MinLen + TCPMinLen + plSize))
	packet.TCP.DataOff = packet.TCP.DataOff | 0x50

	if hwtxchecksum {
		packet.IPv4.HdrChecksum = 0
		low.SetTXIPv4TCPOLFlags(packet.CMbuf, EtherLen, IPv4MinLen)
	}
	return true
}

// InitEmptyIPv4UDPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv4 and UDP headers. This function supposes that IPv4
// header has minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyIPv4UDPPacket(packet *Packet, plSize uint) bool {
	bufSize := plSize + EtherLen + IPv4MinLen + UDPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv4UDPPacket: Cannot append mbuf")
		return false
	}
	packet.ParseIPv4()
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.unparsed() + IPv4MinLen))
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv4MinLen + UDPLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.IPv4.NextProtoID = UDPNumber
	packet.IPv4.VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.IPv4.TotalLength = SwapBytesUint16(uint16(IPv4MinLen + UDPLen + plSize))
	packet.UDP.DgramLen = SwapBytesUint16(uint16(UDPLen + plSize))

	if hwtxchecksum {
		packet.IPv4.HdrChecksum = 0
		low.SetTXIPv4UDPOLFlags(packet.CMbuf, EtherLen, IPv4MinLen)
	}

	return true
}

// InitEmptyIPv4ICMPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv4 and ICMP headers. This function supposes that IPv4
// header has minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyIPv4ICMPPacket(packet *Packet, plSize uint) bool {
	bufSize := plSize + EtherLen + IPv4MinLen + ICMPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv4ICMPPacket: Cannot append mbuf")
		return false
	}
	packet.ParseIPv4()
	packet.ICMP = (*ICMPHdr)(unsafe.Pointer(packet.unparsed() + IPv4MinLen))
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv4MinLen + ICMPLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.IPv4.NextProtoID = ICMPNumber
	packet.IPv4.VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.IPv4.TotalLength = SwapBytesUint16(uint16(IPv4MinLen + ICMPLen + plSize))
	return true
}

// InitEmptyIPv6TCPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv6 and TCP headers. This function supposes that IPv6 and TCP
// headers have minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyIPv6TCPPacket(packet *Packet, plSize uint) bool {
	// TODO support variable header length (ask header length from user)
	bufSize := plSize + EtherLen + IPv6Len + TCPMinLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv6TCPPacket: Cannot append mbuf")
		return false
	}
	packet.ParseIPv6()
	packet.TCP = (*TCPHdr)(unsafe.Pointer(packet.unparsed() + IPv6Len))
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv6Len + TCPMinLen)
	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.IPv6.Proto = TCPNumber
	packet.IPv6.PayloadLen = SwapBytesUint16(uint16(TCPMinLen + plSize))
	packet.IPv6.VtcFlow = SwapBytesUint32(0x60 << 24) // IP version
	packet.TCP.DataOff = packet.TCP.DataOff | 0x50

	if hwtxchecksum {
		low.SetTXIPv6TCPOLFlags(packet.CMbuf, EtherLen, IPv6Len)
	}
	return true
}

// InitEmptyIPv6UDPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv6 and UDP headers. This function supposes that IPv6
// header has minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyIPv6UDPPacket(packet *Packet, plSize uint) bool {
	bufSize := plSize + EtherLen + IPv6Len + UDPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv6UDPPacket: Cannot append mbuf")
		return false
	}
	packet.ParseIPv6()
	packet.UDP = (*UDPHdr)(unsafe.Pointer(packet.unparsed() + IPv6Len))
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv6Len + UDPLen)

	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.IPv6.Proto = UDPNumber
	packet.IPv6.PayloadLen = SwapBytesUint16(uint16(UDPLen + plSize))
	packet.IPv6.VtcFlow = SwapBytesUint32(0x60 << 24) // IP version
	packet.UDP.DgramLen = SwapBytesUint16(uint16(UDPLen + plSize))

	if hwtxchecksum {
		low.SetTXIPv6UDPOLFlags(packet.CMbuf, EtherLen, IPv6Len)
	}
	return true
}

// InitEmptyIPv6ICMPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv6 and ICMP headers.
func InitEmptyIPv6ICMPPacket(packet *Packet, plSize uint) bool {
	bufSize := plSize + EtherLen + IPv6Len + ICMPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv6ICMPPacket: Cannot append mbuf")
		return false
	}
	packet.ParseIPv6()
	packet.ICMP = (*ICMPHdr)(unsafe.Pointer(packet.unparsed() + IPv6Len))
	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv6Len + ICMPLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.IPv6.Proto = ICMPNumber
	packet.IPv6.PayloadLen = SwapBytesUint16(uint16(UDPLen + plSize))
	packet.IPv6.VtcFlow = SwapBytesUint32(0x60 << 24) // IP version
	return true
}

func SetHWCksumOLFlags(packet *Packet) {
	if packet.Ether.EtherType == SwapBytesUint16(IPV4Number) {
		packet.IPv4.HdrChecksum = 0
		if packet.IPv4.NextProtoID == UDPNumber {
			low.SetTXIPv4UDPOLFlags(packet.CMbuf, EtherLen, IPv4MinLen)
		} else if packet.IPv4.NextProtoID == TCPNumber {
			low.SetTXIPv4TCPOLFlags(packet.CMbuf, EtherLen, IPv4MinLen)
		}
	} else if packet.Ether.EtherType == SwapBytesUint16(IPV6Number) {
		if packet.IPv6.Proto == UDPNumber {
			low.SetTXIPv6UDPOLFlags(packet.CMbuf, EtherLen, IPv6Len)
		} else if packet.IPv6.Proto == TCPNumber {
			low.SetTXIPv6TCPOLFlags(packet.CMbuf, EtherLen, IPv6Len)
		}
	}
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
	packet.Ether = (*EtherHdr)(unsafe.Pointer(uintptr(unsafe.Pointer(packet.Ether)) - uintptr(length)))
	for i := uint(0); i < start; i++ {
		*(*uint8)(unsafe.Pointer(packet.Start() + uintptr(i))) = *(*uint8)(unsafe.Pointer(packet.Start() + uintptr(i+length)))
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
		*(*uint8)(unsafe.Pointer(packet.Start() + uintptr(i))) = *(*uint8)(unsafe.Pointer(packet.Start() + uintptr(i-length)))
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
		*(*uint8)(unsafe.Pointer(packet.Start() + uintptr(i+int(length)))) = *(*uint8)(unsafe.Pointer(packet.Start() + uintptr(i)))
	}
	packet.Ether = (*EtherHdr)(unsafe.Pointer(uintptr(unsafe.Pointer(packet.Ether)) + uintptr(length)))
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
		*(*uint8)(unsafe.Pointer(packet.Start() + uintptr(i))) = *(*uint8)(unsafe.Pointer(packet.Start() + uintptr(i+length)))
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
		*(*byte)(unsafe.Pointer(packet.Start() + uintptr(start+i))) = bytes[i]
	}
	return true
}

// IPv4 converts four element address to uint32 representation
func IPv4(a byte, b byte, c byte, d byte) uint32 {
	return uint32(d)<<24 | uint32(c)<<16 | uint32(b)<<8 | uint32(a)
}
