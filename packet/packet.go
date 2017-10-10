// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package packet provides functionality for fast parsing and generating
// of packets with known structure.
// The following header types are supported:
//      * L2 Ethernet
//      * L3 IPv4 and IPv6
//      * L4 TCP, UDP and ICMP
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
//		GeneratePacketFromByte function
// This function get slice of bytes of any size. Returns packet which contains only these bytes.
//              CreateEmpty function family
// There is family of functions to generate empty packets of predefined
// size with known header types. All these functions return empty but parsed
// packet with required protocol headers and preallocated space for payload.
// All these functions get size of payload as argument. After using one of
// this functions user can fill any required fields headers of the packet and
// also fill payload.
package packet

import (
	"fmt"
	"unsafe"

	. "github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
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

// The following structures must be consistent with these C duplications

// EtherHdr L2 header from DPDK: lib/librte_ether/rte_ehter.h
type EtherHdr struct {
	DAddr     [EtherAddrLen]uint8 // Destination address
	SAddr     [EtherAddrLen]uint8 // Source address
	EtherType uint16              // Frame type
}

func (hdr *EtherHdr) String() string {
	r0 := fmt.Sprintf("L2 protocol: Ethernet\nEtherType: 0x%02x\n", hdr.EtherType)
	s := hdr.SAddr
	r1 := fmt.Sprintf("Ethernet Source: %02x:%02x:%02x:%02x:%02x:%02x\n", s[0], s[1], s[2], s[3], s[4], s[5])
	d := hdr.DAddr
	r2 := fmt.Sprintf("Ethernet Destination: %02x:%02x:%02x:%02x:%02x:%02x\n", d[0], d[1], d[2], d[3], d[4], d[5])
	return r0 + r1 + r2
}

// VLANHdr 802.1Q VLAN header which may be added right after EtherHdr
// if EtherHdr.EtherType is equal to VLANNumber
type VLANHdr struct {
	TCI       uint16 // Tag control information. Contains PCP, DEI and VID bit-fields
	EtherType uint16 // Real EtherType instead of VLANNumber in EtherHdr.EtherType
}

func (hdr *VLANHdr) String() string {
	return fmt.Sprintf(`L2 VLAN:\n
TCI: 0x%02x (priority: %d, drop %d, ID: %d)\n
EtherType: 0x%02x\n`, hdr.TCI, byte(hdr.TCI>>13), (hdr.TCI>>12)&1, hdr.TCI&0xfff, hdr.EtherType)
}

// IPv4Hdr L3 header from DPDK: lib/librte_net/rte_ip.h
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

// IPv6Hdr L3 header from DPDK: lib/librte_net/rte_ip.h
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

// TCPHdr L4 header from DPDK: lib/librte_net/rte_tcp.h
type TCPHdr struct {
	SrcPort  uint16   // TCP source port
	DstPort  uint16   // TCP destination port
	SentSeq  uint32   // TX data sequence number
	RecvAck  uint32   // RX data acknowledgement sequence number
	DataOff  uint8    // Data offset
	TCPFlags TCPFlags // TCP flags
	RxWin    uint16   // RX flow control window
	Cksum    uint16   // TCP checksum
	TCPUrp   uint16   // TCP urgent pointer, if any
}

func (hdr *TCPHdr) String() string {
	r0 := "        L4 protocol: TCP\n"
	r1 := fmt.Sprintf("        L4 Source: %d\n", SwapBytesUint16(hdr.SrcPort))
	r2 := fmt.Sprintf("        L4 Destination: %d\n", SwapBytesUint16(hdr.DstPort))
	return r0 + r1 + r2
}

// UDPHdr L4 header from DPDK: lib/librte_net/rte_udp.h
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

// ICMPHdr L4 header.
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
	L3   unsafe.Pointer // Pointer to L3 header in mbuf
	L4   unsafe.Pointer // Pointer to L4 header in mbuf
	Data unsafe.Pointer // Pointer to the packet payload data

	// Last two fields of this structure is filled during InitMbuf macros inside low.c file
	// Need to change low.c for all changes in these fields or adding/removing fields before them.
	Ether *EtherHdr // Pointer to L2 header in mbuf. It is always parsed and point beginning of packet.
	CMbuf *low.Mbuf // Private pointer to mbuf. Users shouldn't know anything about mbuf

	Next *Packet // non nil if packet consists of several chained mbufs
}

func (packet *Packet) unparsed() uintptr {
	ptr := uintptr(unsafe.Pointer(packet.Ether)) + EtherLen

	if packet.Ether.EtherType == SwapBytesUint16(VLANNumber) {
		ptr += VLANLen
	}
	return ptr
}

// Start function return pointer to first byte of packet
// Which is the same as first byte of ethernet protocol header
func (packet *Packet) Start() uintptr {
	return uintptr(unsafe.Pointer(packet.Ether))
}

// ParseL3 set poinetr to start of L3 header
func (packet *Packet) ParseL3() {
	packet.L3 = unsafe.Pointer(packet.unparsed())
}

// GetVLAN returns VLAN header pointer if it is present in the packet.
func (packet *Packet) GetVLAN() *VLANHdr {
	if packet.Ether.EtherType == SwapBytesUint16(VLANNumber) {
		return (*VLANHdr)(unsafe.Pointer(uintptr(unsafe.Pointer(packet.Ether)) + EtherLen))
	}
	return nil
}

// GetIPv4 ensures if EtherType is IPv4 and cast L3 poinetr to IPv4Hdr type.
func (packet *Packet) GetIPv4() *IPv4Hdr {
	if packet.Ether.EtherType == SwapBytesUint16(IPV4Number) {
		return (*IPv4Hdr)(packet.L3)
	}
	return nil
}

// GetIPv4CheckVLAN ensures if EtherType is IPv4 and cast L3 poinetr
// to IPv4Hdr type. If EtherType has VLANNumber, then VLAN header
// EtherType is checked instead.
func (packet *Packet) GetIPv4CheckVLAN() *IPv4Hdr {
	if packet.Ether.EtherType == SwapBytesUint16(IPV4Number) {
		return (*IPv4Hdr)(packet.L3)
	} else if packet.Ether.EtherType == SwapBytesUint16(VLANNumber) {
		vhdr := packet.GetVLAN()
		if vhdr.EtherType == SwapBytesUint16(IPV4Number) {
			return (*IPv4Hdr)(packet.L3)
		}
	}
	return nil
}

// GetARP ensures if EtherType is IPv4 and cast L3 poinetr to IPv4Hdr type.
func (packet *Packet) GetARP() *ARPHdr {
	if packet.Ether.EtherType == SwapBytesUint16(ARPNumber) {
		return (*ARPHdr)(packet.L3)
	}
	return nil
}

// GetARPCheckVLAN ensures if EtherType is IPv4 and cast L3 poinetr to
// IPv4Hdr type. If EtherType has VLANNumber, then VLAN header
// EtherType is checked instead.
func (packet *Packet) GetARPCheckVLAN() *ARPHdr {
	if packet.Ether.EtherType == SwapBytesUint16(ARPNumber) {
		return (*ARPHdr)(packet.L3)
	} else if packet.Ether.EtherType == SwapBytesUint16(VLANNumber) {
		vhdr := packet.GetVLAN()
		if vhdr.EtherType == SwapBytesUint16(ARPNumber) {
			return (*ARPHdr)(packet.L3)
		}
	}
	return nil
}

// GetIPv6 ensures if EtherType is IPv6 and cast L3 poinetr to IPv6Hdr type.
func (packet *Packet) GetIPv6() *IPv6Hdr {
	if packet.Ether.EtherType == SwapBytesUint16(IPV6Number) {
		return (*IPv6Hdr)(packet.L3)
	}
	return nil
}

// GetIPv6CheckVLAN ensures if EtherType is IPv6 and cast L3 poinetr
// to IPv6Hdr type. If EtherType has VLANNumber, then VLAN header
// EtherType is checked instead.
func (packet *Packet) GetIPv6CheckVLAN() *IPv6Hdr {
	if packet.Ether.EtherType == SwapBytesUint16(IPV6Number) {
		return (*IPv6Hdr)(packet.L3)
	} else if packet.Ether.EtherType == SwapBytesUint16(VLANNumber) {
		vhdr := packet.GetVLAN()
		if vhdr.EtherType == SwapBytesUint16(IPV6Number) {
			return (*IPv6Hdr)(packet.L3)
		}
	}
	return nil
}

// ParseL4ForIPv4 set L4 to start of L4 header, if L3 protocol is IPv4.
func (packet *Packet) ParseL4ForIPv4() {
	packet.L4 = unsafe.Pointer(packet.unparsed() + uintptr((packet.GetIPv4().VersionIhl&0x0f)<<2))
}

// ParseL4ForIPv6 set L4 to start of L4 header, if L3 protocol is IPv6.
func (packet *Packet) ParseL4ForIPv6() {
	packet.L4 = unsafe.Pointer(packet.unparsed() + uintptr(IPv6Len))
}

// GetTCPForIPv4 ensures if L4 type is TCP and cast L4 pointer to TCPHdr type.
func (packet *Packet) GetTCPForIPv4() *TCPHdr {
	if packet.GetIPv4().NextProtoID == TCPNumber {
		return (*TCPHdr)(packet.L4)
	}
	return nil
}

// GetTCPForIPv6 ensures if L4 type is TCP and cast L4 pointer to *TCPHdr type.
func (packet *Packet) GetTCPForIPv6() *TCPHdr {
	if packet.GetIPv6().Proto == TCPNumber {
		return (*TCPHdr)(packet.L4)
	}
	return nil
}

// GetUDPForIPv4 ensures if L4 type is UDP and cast L4 pointer to *UDPHdr type.
func (packet *Packet) GetUDPForIPv4() *UDPHdr {
	if packet.GetIPv4().NextProtoID == UDPNumber {
		return (*UDPHdr)(packet.L4)
	}
	return nil
}

// GetUDPForIPv6 ensures if L4 type is UDP and cast L4 pointer to *UDPHdr type.
func (packet *Packet) GetUDPForIPv6() *UDPHdr {
	if packet.GetIPv6().Proto == UDPNumber {
		return (*UDPHdr)(packet.L4)
	}
	return nil
}

// GetICMPForIPv4 ensures if L4 type is ICMP and cast L4 poinetr to *ICMPHdr type.
// L3 supposed to be parsed before and of IPv4 type.
func (packet *Packet) GetICMPForIPv4() *ICMPHdr {
	if packet.GetIPv4().NextProtoID == ICMPNumber {
		return (*ICMPHdr)(packet.L4)
	}
	return nil
}

// GetICMPForIPv6 ensures if L4 type is ICMP and cast L4 poinetr to *ICMPHdr type.
// L3 supposed to be parsed before and of IPv6 type.
func (packet *Packet) GetICMPForIPv6() *ICMPHdr {
	if packet.GetIPv6().Proto == ICMPNumber {
		return (*ICMPHdr)(packet.L4)
	}
	return nil
}

// ParseAllKnownL3 parses L3 field and returns pointers to parsed headers.
func (packet *Packet) ParseAllKnownL3() (*IPv4Hdr, *IPv6Hdr) {
	packet.ParseL3()
	return packet.GetIPv4(), packet.GetIPv6()
}

// ParseAllKnownL4ForIPv4 parses L4 field if L3 type is IPv4 and returns pointers to parsed headers.
func (packet *Packet) ParseAllKnownL4ForIPv4() (*TCPHdr, *UDPHdr, *ICMPHdr) {
	packet.ParseL4ForIPv4()
	return packet.GetTCPForIPv4(), packet.GetUDPForIPv4(), packet.GetICMPForIPv4()
}

// ParseAllKnownL4ForIPv6 parses L4 field if L3 type is IPv6 and returns pointers to parsed headers.
func (packet *Packet) ParseAllKnownL4ForIPv6() (*TCPHdr, *UDPHdr, *ICMPHdr) {
	packet.ParseL4ForIPv6()
	return packet.GetTCPForIPv6(), packet.GetUDPForIPv6(), packet.GetICMPForIPv6()
}

// ParseL7 fills pointers to all supported headers and data field.
func (packet *Packet) ParseL7(protocol uint) {
	switch protocol {
	case TCPNumber:
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(((*TCPHdr)(packet.L4)).DataOff&0xf0)>>2)
	case UDPNumber:
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(UDPLen))
	case ICMPNumber:
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(ICMPLen))
	}
}

// ParseData parses L3, L4 and fills the field packet.Data.
// returns 0 in case of success and -1 in case of
// failure to parse L3 or L4.
func (packet *Packet) ParseData() int {
	var pktTCP *TCPHdr
	var pktUDP *UDPHdr
	var pktICMP *ICMPHdr

	pktIPv4, pktIPv6 := packet.ParseAllKnownL3()
	if pktIPv4 != nil {
		pktTCP, pktUDP, pktICMP = packet.ParseAllKnownL4ForIPv4()
	} else if pktIPv6 != nil {
		pktTCP, pktUDP, pktICMP = packet.ParseAllKnownL4ForIPv6()
	}

	if pktTCP != nil {
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(((*TCPHdr)(packet.L4)).DataOff&0xf0)>>2)
	} else if pktUDP != nil {
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(UDPLen))
	} else if pktICMP != nil {
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(ICMPLen))
	} else {
		return -1
	}
	return 0
}

// ExtractPacketAddr extracts packet structure from mbuf used in package flow
func ExtractPacketAddr(IN uintptr) uintptr {
	return IN + mbufStructSize
}

// ToPacket should be unexported, used in flow package.
func ToPacket(IN uintptr) *Packet {
	return (*Packet)(unsafe.Pointer(IN))
}

// ExtractPacket extracts packet structure from mbuf used in package flow.
func ExtractPacket(IN uintptr) *Packet {
	return ToPacket(ExtractPacketAddr(IN))
}

// SetHWTXChecksumFlag should not be exported but it is used in flow.
func SetHWTXChecksumFlag(flag bool) {
	hwtxchecksum = flag
}

// ExtractPackets creates vector of packets by calling ExtractPacket function
// is unexported, used in flow package
func ExtractPackets(packet []*Packet, IN []uintptr, n uint) {
	for i := uint(0); i < n; i++ {
		packet[i] = ExtractPacket(IN[i])
	}
}

// GeneratePacketFromByte function gets non-initialized packet and slice of bytes of any size.
// Initializes input packet and fills it with these bytes.
func GeneratePacketFromByte(packet *Packet, data []byte) bool {
	if low.AppendMbuf(packet.CMbuf, uint(len(data))) == false {
		LogWarning(Debug, "GeneratePacketFromByte: Cannot append mbuf")
		return false
	}
	low.WriteDataToMbuf(packet.CMbuf, data)
	return true
}

// All following functions set Data pointer because it is assumed that user
// need to generate real packets with some information.

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

	// After packet is parsed, we can write to packet struct known protocol types
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv4MinLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.ParseL3()
	packet.GetIPv4().VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.GetIPv4().TotalLength = SwapBytesUint16(uint16(IPv4MinLen + plSize))
	packet.GetIPv4().NextProtoID = NoNextHeader
	if hwtxchecksum {
		packet.GetIPv4().HdrChecksum = 0
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
	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv6Len)

	packet.ParseL3()
	packet.GetIPv6().PayloadLen = SwapBytesUint16(uint16(plSize))
	packet.GetIPv6().VtcFlow = SwapBytesUint32(0x60 << 24) // IP version
	packet.GetIPv6().Proto = NoNextHeader

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
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv4MinLen + TCPMinLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.ParseL3()
	packet.GetIPv4().NextProtoID = TCPNumber
	packet.GetIPv4().VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.GetIPv4().TotalLength = SwapBytesUint16(uint16(IPv4MinLen + TCPMinLen + plSize))

	packet.ParseL4ForIPv4()
	packet.GetTCPForIPv4().DataOff = packet.GetTCPForIPv4().DataOff | 0x50 // TODO check

	if hwtxchecksum {
		packet.GetIPv4().HdrChecksum = 0
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
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv4MinLen + UDPLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.ParseL3()
	packet.GetIPv4().NextProtoID = UDPNumber
	packet.GetIPv4().VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.GetIPv4().TotalLength = SwapBytesUint16(uint16(IPv4MinLen + UDPLen + plSize))

	packet.ParseL4ForIPv4()
	packet.GetUDPForIPv4().DgramLen = SwapBytesUint16(uint16(UDPLen + plSize))

	if hwtxchecksum {
		packet.GetIPv4().HdrChecksum = 0
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
	packet.Ether.EtherType = SwapBytesUint16(IPV4Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv4MinLen + ICMPLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.ParseL3()
	packet.GetIPv4().NextProtoID = ICMPNumber
	packet.GetIPv4().VersionIhl = 0x45 // Ipv4, IHL = 5 (min header len)
	packet.GetIPv4().TotalLength = SwapBytesUint16(uint16(IPv4MinLen + ICMPLen + plSize))
	packet.ParseL4ForIPv4()
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
	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv6Len + TCPMinLen)

	packet.ParseL3()
	packet.GetIPv6().Proto = TCPNumber
	packet.GetIPv6().PayloadLen = SwapBytesUint16(uint16(TCPMinLen + plSize))
	packet.GetIPv6().VtcFlow = SwapBytesUint32(0x60 << 24) // IP version

	packet.ParseL4ForIPv6()
	packet.GetTCPForIPv6().DataOff = packet.GetTCPForIPv6().DataOff | 0x50

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
	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv6Len + UDPLen)

	packet.ParseL3()
	packet.GetIPv6().Proto = UDPNumber
	packet.GetIPv6().PayloadLen = SwapBytesUint16(uint16(UDPLen + plSize))
	packet.GetIPv6().VtcFlow = SwapBytesUint32(0x60 << 24) // IP version

	packet.ParseL4ForIPv6()
	packet.GetUDPForIPv6().DgramLen = SwapBytesUint16(uint16(UDPLen + plSize))

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
	packet.Ether.EtherType = SwapBytesUint16(IPV6Number)
	packet.Data = unsafe.Pointer(packet.unparsed() + IPv6Len + ICMPLen)

	// Next fields not required by pktgen to accept packet. But set anyway
	packet.ParseL3()
	packet.GetIPv6().Proto = ICMPNumber
	packet.GetIPv6().PayloadLen = SwapBytesUint16(uint16(UDPLen + plSize))
	packet.GetIPv6().VtcFlow = SwapBytesUint32(0x60 << 24) // IP version
	packet.ParseL4ForIPv6()
	return true
}

// SetHWCksumOLFlags sets hardware offloading flags to packet
func SetHWCksumOLFlags(packet *Packet) {
	ipv4, ipv6 := packet.ParseAllKnownL3()
	if ipv4 != nil {
		packet.GetIPv4().HdrChecksum = 0
		tcp, udp, _ := packet.ParseAllKnownL4ForIPv4()
		if tcp != nil {
			low.SetTXIPv4TCPOLFlags(packet.CMbuf, EtherLen, IPv4MinLen)
		} else if udp != nil {
			low.SetTXIPv4UDPOLFlags(packet.CMbuf, EtherLen, IPv4MinLen)
		}
	} else if ipv6 != nil {
		tcp, udp, _ := packet.ParseAllKnownL4ForIPv6()
		if tcp != nil {
			low.SetTXIPv6TCPOLFlags(packet.CMbuf, EtherLen, IPv6Len)
		} else if udp != nil {
			low.SetTXIPv6UDPOLFlags(packet.CMbuf, EtherLen, IPv6Len)
		}
	}
}

// SwapBytesUint16 swaps uint16 in Little Endian and Big Endian
func SwapBytesUint16(x uint16) uint16 {
	return x<<8 | x>>8
}

// SwapBytesUint32 swaps uint32 in Little Endian and Big Endian
func SwapBytesUint32(x uint32) uint32 {
	return ((x & 0x000000ff) << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | ((x & 0xff000000) >> 24)
}

// GetRawPacketBytes returns all bytes from this packet. Not zero-copy.
func (packet *Packet) GetRawPacketBytes() []byte {
	return low.GetRawPacketBytesMbuf(packet.CMbuf)
}

// GetPacketLen returns length of this packet. Sum of length of all segments if scattered.
func (packet *Packet) GetPacketLen() uint {
	return low.GetPktLenMbuf(packet.CMbuf)
}

// GetPacketSegmentLen returns length of this segment of packet. It is equal to whole length if packet not scattered
func (packet *Packet) GetPacketSegmentLen() uint {
	return low.GetDataLenMbuf(packet.CMbuf)
}

// TODO change this for scattered packet case (multiple mbufs)
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

// TODO change this for scattered packet case (multiple mbufs)
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

// TODO change this for scattered packet case (multiple mbufs)
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

// TODO change this for scattered packet case (multiple mbufs)
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
