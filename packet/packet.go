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
// reasons NFF-GO provides a set of functions each of them parse exact network level.
//
// Packet parsing
//
// Family of parsing functions can parse packets with known structure of headers
// and parse exactly required protocols.
//
// NFF-GO provides two groups of parsing functions:
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

	. "github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/internal/low"
	"github.com/intel-go/nff-go/types"
)

var mbufStructSize uintptr
var hwtxchecksum bool
var nonPerfMempool *low.Mempool

func init() {
	var t1 low.Mbuf
	mbufStructSize = unsafe.Sizeof(t1)
	var t2 Packet
	packetStructSize := unsafe.Sizeof(t2)
	if err := low.SetPacketStructSize(int(packetStructSize)); err != nil {
		LogFatal(Debug, err)
	}
}

// TODO Add function to write user data after headers and set "data" field

// The following structures must be consistent with these C duplications

// EtherHdr L2 header from DPDK: lib/librte_ether/rte_ehter.h
type EtherHdr struct {
	DAddr     types.MACAddress // Destination address
	SAddr     types.MACAddress // Source address
	EtherType uint16           // Frame type
}

func (hdr *EtherHdr) String() string {
	return fmt.Sprintf(`L2 protocol: Ethernet, EtherType: 0x%04x (%s)
Ethernet Source: %s
Ethernet Destination: %s
`,
		hdr.EtherType, getEtherTypeName(hdr.EtherType),
		hdr.SAddr.String(),
		hdr.DAddr.String())
}

var (
	etherTypeNameLookupTable = map[uint16]string{
		types.SwapIPV4Number: "IPv4",
		types.SwapARPNumber:  "ARP",
		types.SwapVLANNumber: "VLAN",
		types.SwapMPLSNumber: "MPLS",
		types.SwapIPV6Number: "IPv6",
	}
)

func getEtherTypeName(et uint16) string {
	ret, ok := etherTypeNameLookupTable[et]
	if !ok {
		return "unknown"
	}
	return ret
}

// IPv4Hdr L3 header from DPDK: lib/librte_net/rte_ip.h
type IPv4Hdr struct {
	VersionIhl     uint8             // version and header length
	TypeOfService  uint8             // type of service
	TotalLength    uint16            // length of packet
	PacketID       uint16            // packet ID
	FragmentOffset uint16            // fragmentation offset
	TimeToLive     uint8             // time to live
	NextProtoID    uint8             // protocol ID
	HdrChecksum    uint16            // header checksum
	SrcAddr        types.IPv4Address // source address
	DstAddr        types.IPv4Address // destination address
}

func (hdr *IPv4Hdr) String() string {
	r0 := "    L3 protocol: IPv4\n"
	r1 := "    IPv4 Source: " + hdr.SrcAddr.String() + "\n"
	r2 := "    IPv4 Destination: " + hdr.DstAddr.String() + "\n"
	return r0 + r1 + r2
}

// IPv6Hdr L3 header from DPDK: lib/librte_net/rte_ip.h
type IPv6Hdr struct {
	VtcFlow    uint32            // IP version, traffic class & flow label
	PayloadLen uint16            // IP packet length - includes sizeof(ip_header)
	Proto      uint8             // Protocol, next header
	HopLimits  uint8             // Hop limits
	SrcAddr    types.IPv6Address // IP address of source host
	DstAddr    types.IPv6Address // IP address of destination host(s)
}

func (hdr *IPv6Hdr) String() string {
	return fmt.Sprintf(`    L3 protocol: IPv6
    IPv6 Source: %s
    IPv6 Destination %s
`, hdr.SrcAddr.String(), hdr.DstAddr.String())
}

// TCPHdr L4 header from DPDK: lib/librte_net/rte_tcp.h
type TCPHdr struct {
	SrcPort  uint16         // TCP source port
	DstPort  uint16         // TCP destination port
	SentSeq  uint32         // TX data sequence number
	RecvAck  uint32         // RX data acknowledgement sequence number
	DataOff  uint8          // Data offset
	TCPFlags types.TCPFlags // TCP flags
	RxWin    uint16         // RX flow control window
	Cksum    uint16         // TCP checksum
	TCPUrp   uint16         // TCP urgent pointer, if any
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

// Packet is a set of pointers in NFF-GO library. Each pointer points to one of five headers:
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

func (packet *Packet) unparsed() unsafe.Pointer {
	ether := unsafe.Pointer(packet.Ether)
	return unsafe.Pointer(uintptr(ether) + types.EtherLen)
}

// StartAtOffset function return pointer to first byte of packet
// with given offset.
func (packet *Packet) StartAtOffset(offset uintptr) unsafe.Pointer {
	start := unsafe.Pointer(packet.Ether)
	return unsafe.Pointer(uintptr(start) + offset)
}

// ParseL3 set pointer to start of L3 header
func (packet *Packet) ParseL3() {
	packet.L3 = packet.unparsed()
}

// GetIPv4 ensures if EtherType is IPv4 and casts L3 pointer to IPv4Hdr type.
func (packet *Packet) GetIPv4() *IPv4Hdr {
	if packet.Ether.EtherType == SwapBytesUint16(types.IPV4Number) {
		return (*IPv4Hdr)(packet.L3)
	}
	return nil
}

// GetIPv4NoCheck casts L3 pointer to IPv4Hdr type.
func (packet *Packet) GetIPv4NoCheck() *IPv4Hdr {
	return (*IPv4Hdr)(packet.L3)
}

// GetARP ensures if EtherType is ARP and casts L3 pointer to ARPHdr type.
func (packet *Packet) GetARP() *ARPHdr {
	if packet.Ether.EtherType == SwapBytesUint16(types.ARPNumber) {
		return (*ARPHdr)(packet.L3)
	}
	return nil
}

// GetARPNoCheck casts L3 pointer to ARPHdr type.
func (packet *Packet) GetARPNoCheck() *ARPHdr {
	return (*ARPHdr)(packet.L3)
}

// GetIPv6 ensures if EtherType is IPv6 and cast L3 pointer to IPv6Hdr type.
func (packet *Packet) GetIPv6() *IPv6Hdr {
	if packet.Ether.EtherType == SwapBytesUint16(types.IPV6Number) {
		return (*IPv6Hdr)(packet.L3)
	}
	return nil
}

// GetIPv6NoCheck ensures if EtherType is IPv6 and cast L3 pointer to
// IPv6Hdr type.
func (packet *Packet) GetIPv6NoCheck() *IPv6Hdr {
	return (*IPv6Hdr)(packet.L3)
}

// ParseL4ForIPv4 set L4 to start of L4 header, if L3 protocol is IPv4.
func (packet *Packet) ParseL4ForIPv4() {
	packet.L4 = unsafe.Pointer(uintptr(packet.L3) + uintptr((packet.GetIPv4NoCheck().VersionIhl&0x0f)<<2))
}

// ParseL4ForIPv6 set L4 to start of L4 header, if L3 protocol is IPv6.
func (packet *Packet) ParseL4ForIPv6() {
	packet.L4 = unsafe.Pointer(uintptr(packet.L3) + uintptr(types.IPv6Len))
}

// GetTCPForIPv4 ensures if L4 type is TCP and cast L4 pointer to TCPHdr type.
func (packet *Packet) GetTCPForIPv4() *TCPHdr {
	if packet.GetIPv4NoCheck().NextProtoID == types.TCPNumber {
		return (*TCPHdr)(packet.L4)
	}
	return nil
}

// GetTCPNoCheck casts L4 pointer to TCPHdr type.
func (packet *Packet) GetTCPNoCheck() *TCPHdr {
	return (*TCPHdr)(packet.L4)
}

// GetTCPForIPv6 ensures if L4 type is TCP and cast L4 pointer to *TCPHdr type.
func (packet *Packet) GetTCPForIPv6() *TCPHdr {
	if packet.GetIPv6NoCheck().Proto == types.TCPNumber {
		return (*TCPHdr)(packet.L4)
	}
	return nil
}

// GetUDPForIPv4 ensures if L4 type is UDP and cast L4 pointer to *UDPHdr type.
func (packet *Packet) GetUDPForIPv4() *UDPHdr {
	if packet.GetIPv4NoCheck().NextProtoID == types.UDPNumber {
		return (*UDPHdr)(packet.L4)
	}
	return nil
}

// GetUDPNoCheck casts L4 pointer to *UDPHdr type.
func (packet *Packet) GetUDPNoCheck() *UDPHdr {
	return (*UDPHdr)(packet.L4)
}

// GetUDPForIPv6 ensures if L4 type is UDP and cast L4 pointer to *UDPHdr type.
func (packet *Packet) GetUDPForIPv6() *UDPHdr {
	if packet.GetIPv6NoCheck().Proto == types.UDPNumber {
		return (*UDPHdr)(packet.L4)
	}
	return nil
}

// GetICMPForIPv4 ensures if L4 type is ICMP and cast L4 pointer to *ICMPHdr type.
// L3 supposed to be parsed before and of IPv4 type.
func (packet *Packet) GetICMPForIPv4() *ICMPHdr {
	if packet.GetIPv4NoCheck().NextProtoID == types.ICMPNumber {
		return (*ICMPHdr)(packet.L4)
	}
	return nil
}

// GetICMPNoCheck casts L4 pointer to *ICMPHdr type.
func (packet *Packet) GetICMPNoCheck() *ICMPHdr {
	return (*ICMPHdr)(packet.L4)
}

// GetICMPForIPv6 ensures if L4 type is ICMP and cast L4 pointer to *ICMPHdr type.
// L3 supposed to be parsed before and of IPv6 type.
func (packet *Packet) GetICMPForIPv6() *ICMPHdr {
	if packet.GetIPv6NoCheck().Proto == types.ICMPv6Number {
		return (*ICMPHdr)(packet.L4)
	}
	return nil
}

// ParseAllKnownL3 parses L3 field and returns pointers to parsed headers.
func (packet *Packet) ParseAllKnownL3() (*IPv4Hdr, *IPv6Hdr, *ARPHdr) {
	packet.ParseL3()
	if packet.GetIPv4() != nil {
		return packet.GetIPv4NoCheck(), nil, nil
	} else if packet.GetIPv6() != nil {
		return nil, packet.GetIPv6NoCheck(), nil
	} else if packet.GetARP() != nil {
		return nil, nil, packet.GetARPNoCheck()
	}
	return nil, nil, nil
}

// ParseAllKnownL4ForIPv4 parses L4 field if L3 type is IPv4 and returns pointers to parsed headers.
func (packet *Packet) ParseAllKnownL4ForIPv4() (*TCPHdr, *UDPHdr, *ICMPHdr) {
	packet.ParseL4ForIPv4()
	if packet.GetTCPForIPv4() != nil {
		return packet.GetTCPNoCheck(), nil, nil
	} else if packet.GetUDPForIPv4() != nil {
		return nil, packet.GetUDPNoCheck(), nil
	} else if packet.GetICMPForIPv4() != nil {
		return nil, nil, packet.GetICMPNoCheck()
	}
	return nil, nil, nil
}

// ParseAllKnownL4ForIPv6 parses L4 field if L3 type is IPv6 and returns pointers to parsed headers.
func (packet *Packet) ParseAllKnownL4ForIPv6() (*TCPHdr, *UDPHdr, *ICMPHdr) {
	packet.ParseL4ForIPv6()
	if packet.GetTCPForIPv6() != nil {
		return packet.GetTCPNoCheck(), nil, nil
	} else if packet.GetUDPForIPv6() != nil {
		return nil, packet.GetUDPNoCheck(), nil
	} else if packet.GetICMPForIPv6() != nil {
		return nil, nil, packet.GetICMPNoCheck()
	}
	return nil, nil, nil
}

// ParseL7 fills pointers to all supported headers and data field.
func (packet *Packet) ParseL7(protocol uint) {
	switch protocol {
	case types.TCPNumber:
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(((*TCPHdr)(packet.L4)).DataOff&0xf0)>>2)
	case types.UDPNumber:
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(types.UDPLen))
	case types.ICMPNumber:
		fallthrough
	case types.ICMPv6Number:
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(types.ICMPLen))
	}
}

// ParseData parses L3, L4 and fills the field packet.Data.
// returns 0 in case of success and -1 in case of
// failure to parse L3 or L4.
func (packet *Packet) ParseData() int {
	var pktTCP *TCPHdr
	var pktUDP *UDPHdr
	var pktICMP *ICMPHdr

	pktIPv4, pktIPv6, _ := packet.ParseAllKnownL3()
	if pktIPv4 != nil {
		pktTCP, pktUDP, pktICMP = packet.ParseAllKnownL4ForIPv4()
	} else if pktIPv6 != nil {
		pktTCP, pktUDP, pktICMP = packet.ParseAllKnownL4ForIPv6()
	}

	if pktTCP != nil {
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(((*TCPHdr)(packet.L4)).DataOff&0xf0)>>2)
	} else if pktUDP != nil {
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(types.UDPLen))
	} else if pktICMP != nil {
		packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(types.ICMPLen))
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

// ToUintptr returns start of mbuf for current packet
func (p *Packet) ToUintptr() uintptr {
	return uintptr(unsafe.Pointer(p.CMbuf))
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
	bufSize := plSize + types.EtherLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyPacket: Cannot append mbuf")
		return false
	}
	packet.Data = packet.unparsed()
	return true
}

// InitNextPacket creates new packet with plSize bytes,
// packet is treated as one of segments:
// Data pointer is set to the beginning of packet
// new packet is attached to Next pointer of prev packet
// Return new packet or nil if error
// Function is not performance efficient due to use of single packet allocation
func InitNextPacket(plSize uint, prev *Packet) *Packet {
	packet, err := NewPacket()
	if err != nil || low.AppendMbuf(packet.CMbuf, plSize) == false {
		LogWarning(Debug, "InitNextPacket: Cannot allocate new packet")
		return nil
	}
	packet.Data = unsafe.Pointer(packet.Ether)
	prev.Next = packet
	low.SetNextMbuf(packet.CMbuf, prev.CMbuf)
	return packet
}

func fillIPv4Default(packet *Packet, plLen uint16, nextProto uint8) {
	packet.GetIPv4NoCheck().VersionIhl = types.IPv4VersionIhl
	packet.GetIPv4NoCheck().TotalLength = SwapBytesUint16(plLen)
	packet.GetIPv4NoCheck().NextProtoID = nextProto
	packet.GetIPv4NoCheck().TimeToLive = 64
}

func fillIPv6Default(packet *Packet, totalLen uint16, nextProto uint8) {
	packet.GetIPv6NoCheck().PayloadLen = SwapBytesUint16(totalLen)
	packet.GetIPv6NoCheck().VtcFlow = types.IPv6VtcFlow
	packet.GetIPv6NoCheck().Proto = nextProto
	packet.GetIPv6NoCheck().HopLimits = 255
}

// InitEmptyIPv4Packet initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet and IPv4 headers.
func InitEmptyIPv4Packet(packet *Packet, plSize uint) bool {
	// TODO After mandatory fields, IPv4 header optionally may have options of variable length
	// Now pre-allocate space only for mandatory fields
	bufSize := plSize + types.EtherLen + types.IPv4MinLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv4Packet: Cannot append mbuf")
		return false
	}
	packet.Ether.EtherType = SwapBytesUint16(types.IPV4Number)
	packet.Data = unsafe.Pointer(uintptr(packet.unparsed()) + types.IPv4MinLen)

	packet.ParseL3()
	fillIPv4Default(packet, uint16(types.IPv4MinLen+plSize), types.NoNextHeader)

	if hwtxchecksum {
		packet.GetIPv4NoCheck().HdrChecksum = 0
		low.SetTXIPv4OLFlags(packet.CMbuf, types.EtherLen, types.IPv4MinLen)
	}
	return true
}

// InitEmptyIPv6Packet initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet and IPv6 headers.
func InitEmptyIPv6Packet(packet *Packet, plSize uint) bool {
	bufSize := plSize + types.EtherLen + types.IPv6Len
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv6Packet: Cannot append mbuf")
		return false
	}
	packet.Ether.EtherType = SwapBytesUint16(types.IPV6Number)
	packet.Data = unsafe.Pointer(uintptr(packet.unparsed()) + types.IPv6Len)

	packet.ParseL3()
	fillIPv6Default(packet, uint16(plSize), types.NoNextHeader)
	return true
}

// InitEmptyARPPacket initializes empty ARP packet
func InitEmptyARPPacket(packet *Packet) bool {
	var bufSize uint = types.EtherLen + types.ARPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyARPPacket: Cannot append mbuf")
		return false
	}

	packet.Ether.EtherType = SwapBytesUint16(types.ARPNumber)
	packet.ParseL3()
	return true
}

// InitEmptyIPv4TCPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv4 and TCP headers. This function supposes that IPv4 and TCP
// headers have minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyIPv4TCPPacket(packet *Packet, plSize uint) bool {
	// Now user cannot set explicitly optional fields, so len of header is supposed to be equal to TCPMinLen
	// TODO support variable header length (ask header length from user)
	bufSize := plSize + types.EtherLen + types.IPv4MinLen + types.TCPMinLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyPacket: Cannot append mbuf")
		return false
	}
	packet.Ether.EtherType = SwapBytesUint16(types.IPV4Number)

	packet.ParseL3()
	fillIPv4Default(packet, uint16(types.IPv4MinLen+types.TCPMinLen+plSize), types.TCPNumber)
	packet.ParseL4ForIPv4()
	packet.GetTCPNoCheck().DataOff = types.TCPMinDataOffset
	packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(packet.GetTCPNoCheck().DataOff&0xf0)>>2)

	if hwtxchecksum {
		packet.GetIPv4NoCheck().HdrChecksum = 0
		low.SetTXIPv4TCPOLFlags(packet.CMbuf, types.EtherLen, types.IPv4MinLen)
	}
	return true
}

// InitEmptyIPv4UDPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv4 and UDP headers. This function supposes that IPv4
// header has minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyIPv4UDPPacket(packet *Packet, plSize uint) bool {
	bufSize := plSize + types.EtherLen + types.IPv4MinLen + types.UDPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv4UDPPacket: Cannot append mbuf")
		return false
	}
	packet.Ether.EtherType = SwapBytesUint16(types.IPV4Number)
	packet.Data = unsafe.Pointer(uintptr(packet.unparsed()) + types.IPv4MinLen + types.UDPLen)

	packet.ParseL3()
	fillIPv4Default(packet, uint16(types.IPv4MinLen+types.UDPLen+plSize), types.UDPNumber)
	packet.ParseL4ForIPv4()
	packet.GetUDPNoCheck().DgramLen = SwapBytesUint16(uint16(types.UDPLen + plSize))

	if hwtxchecksum {
		packet.GetIPv4NoCheck().HdrChecksum = 0
		low.SetTXIPv4UDPOLFlags(packet.CMbuf, types.EtherLen, types.IPv4MinLen)
	}
	return true
}

// InitEmptyIPv4ICMPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv4 and ICMP headers. This function supposes that IPv4
// header has minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyIPv4ICMPPacket(packet *Packet, plSize uint) bool {
	bufSize := plSize + types.EtherLen + types.IPv4MinLen + types.ICMPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv4ICMPPacket: Cannot append mbuf")
		return false
	}
	packet.Ether.EtherType = SwapBytesUint16(types.IPV4Number)
	packet.Data = unsafe.Pointer(uintptr(packet.unparsed()) + types.IPv4MinLen + types.ICMPLen)

	packet.ParseL3()
	fillIPv4Default(packet, uint16(types.IPv4MinLen+types.ICMPLen+plSize), types.ICMPNumber)
	packet.ParseL4ForIPv4()
	return true
}

// InitEmptyIPv6TCPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv6 and TCP headers. This function supposes that IPv6 and TCP
// headers have minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyIPv6TCPPacket(packet *Packet, plSize uint) bool {
	// TODO support variable header length (ask header length from user)
	bufSize := plSize + types.EtherLen + types.IPv6Len + types.TCPMinLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv6TCPPacket: Cannot append mbuf")
		return false
	}
	packet.Ether.EtherType = SwapBytesUint16(types.IPV6Number)

	packet.ParseL3()
	fillIPv6Default(packet, uint16(types.TCPMinLen+plSize), types.TCPNumber)
	packet.ParseL4ForIPv6()
	packet.GetTCPNoCheck().DataOff = types.TCPMinDataOffset
	packet.Data = unsafe.Pointer(uintptr(packet.L4) + uintptr(packet.GetTCPNoCheck().DataOff&0xf0)>>2)

	if hwtxchecksum {
		low.SetTXIPv6TCPOLFlags(packet.CMbuf, types.EtherLen, types.IPv6Len)
	}
	return true
}

// InitEmptyIPv6UDPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv6 and UDP headers. This function supposes that IPv6
// header has minimum length. In fact length can be higher due to optional fields.
// Now setting optional fields explicitly is not supported.
func InitEmptyIPv6UDPPacket(packet *Packet, plSize uint) bool {
	bufSize := plSize + types.EtherLen + types.IPv6Len + types.UDPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv6UDPPacket: Cannot append mbuf")
		return false
	}
	packet.Ether.EtherType = SwapBytesUint16(types.IPV6Number)
	packet.Data = unsafe.Pointer(uintptr(packet.unparsed()) + types.IPv6Len + types.UDPLen)

	packet.ParseL3()
	fillIPv6Default(packet, uint16(types.UDPLen+plSize), types.UDPNumber)
	packet.ParseL4ForIPv6()
	packet.GetUDPNoCheck().DgramLen = SwapBytesUint16(uint16(types.UDPLen + plSize))

	if hwtxchecksum {
		low.SetTXIPv6UDPOLFlags(packet.CMbuf, types.EtherLen, types.IPv6Len)
	}
	return true
}

// InitEmptyIPv6ICMPPacket initializes input packet with preallocated plSize of bytes for payload
// and init pointers to Ethernet, IPv6 and ICMP headers.
func InitEmptyIPv6ICMPPacket(packet *Packet, plSize uint) bool {
	bufSize := plSize + types.EtherLen + types.IPv6Len + types.ICMPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		LogWarning(Debug, "InitEmptyIPv6ICMPPacket: Cannot append mbuf")
		return false
	}
	packet.Ether.EtherType = SwapBytesUint16(types.IPV6Number)
	packet.Data = unsafe.Pointer(uintptr(packet.unparsed()) + types.IPv6Len + types.ICMPLen)

	packet.ParseL3()
	fillIPv6Default(packet, uint16(types.ICMPLen+plSize), types.ICMPv6Number)
	packet.ParseL4ForIPv6()
	return true
}

// SwapBytesUint16 swaps uint16 in Little Endian and Big Endian
func SwapBytesUint16(x uint16) uint16 {
	return x<<8 | x>>8
}

// SwapBytesUint32 swaps uint32 in Little Endian and Big Endian
func SwapBytesUint32(x uint32) uint32 {
	return ((x & 0x000000ff) << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | ((x & 0xff000000) >> 24)
}

func SwapBytesIPv4Addr(x types.IPv4Address) types.IPv4Address {
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

// GetPacketPayload returns extracted packet payload as byte array and bool status.
// Works only for protocols, supported by ParseData (IPv4, IPv6, TCP, UDP, ICMP). Not zero-copy.
func (packet *Packet) GetPacketPayload() ([]byte, bool) {
	pktStartAddr := packet.StartAtOffset(0)
	pktBytes := packet.GetRawPacketBytes()
	if packet.ParseData() == -1 {
		return []byte{}, false
	}
	hdrsLen := uintptr(packet.Data) - uintptr(pktStartAddr)
	return pktBytes[hdrsLen:], true
}

// EncapsulateHead adds bytes to packet. start - number of beginning byte, length - number of
// added bytes. This function should be used to add bytes to the first half
// of packet. Return false if error.
// You must not add NoPacketHeadChange option to SystemInit for using this function safely.
// TODO change this for scattered packet case (multiple mbufs)
func (packet *Packet) EncapsulateHead(start uint, length uint) bool {
	if low.PrependMbuf(packet.CMbuf, length) == false {
		return false
	}
	packet.Ether = (*EtherHdr)(unsafe.Pointer(uintptr(unsafe.Pointer(packet.Ether)) - uintptr(length)))
	for i := uint(0); i < start; i++ {
		*(*uint8)(unsafe.Pointer(packet.StartAtOffset(uintptr(i)))) = *(*uint8)(unsafe.Pointer(packet.StartAtOffset(uintptr(i + length))))
	}
	return true
}

// EncapsulateTail adds bytes to packet. start - number of beginning byte, length - number of
// added bytes. This function should be used to add bytes to the second half
// of packet. Return false if error.
// TODO change this for scattered packet case (multiple mbufs)
func (packet *Packet) EncapsulateTail(start uint, length uint) bool {
	if low.AppendMbuf(packet.CMbuf, length) == false {
		return false
	}
	packetLength := packet.GetPacketLen()
	for i := packetLength - 1; int(i) >= int(start+length); i-- {
		*(*uint8)(unsafe.Pointer(packet.StartAtOffset(uintptr(i)))) = *(*uint8)(unsafe.Pointer(packet.StartAtOffset(uintptr(i - length))))
	}
	return true
}

// DecapsulateHead removes bytes from packet. start - number of beginning byte, length - number of
// removed bytes. This function should be used to remove bytes from the first half
// of packet. Return false if error.
// You must not add NoPacketHeadChange option to SystemInit for using this function safely.
// TODO change this for scattered packet case (multiple mbufs)
func (packet *Packet) DecapsulateHead(start uint, length uint) bool {
	if low.AdjMbuf(packet.CMbuf, length) == false {
		return false
	}
	for i := int(start - 1); i >= 0; i-- {
		*(*uint8)(unsafe.Pointer(packet.StartAtOffset(uintptr(i + int(length))))) = *(*uint8)(unsafe.Pointer(packet.StartAtOffset(uintptr(i))))
	}
	packet.Ether = (*EtherHdr)(unsafe.Pointer(uintptr(unsafe.Pointer(packet.Ether)) + uintptr(length)))
	return true
}

// DecapsulateTail removes bytes from packet. start - number of beginning byte, length - number of
// removed bytes. This function should be used to remove bytes from the second half
// of packet. Return false if error.
// TODO change this for scattered packet case (multiple mbufs)
func (packet *Packet) DecapsulateTail(start uint, length uint) bool {
	packetLength := packet.GetPacketLen() // This won't be changed by next operation
	if low.TrimMbuf(packet.CMbuf, length) == false {
		return false
	}
	for i := start; i < packetLength; i++ {
		*(*uint8)(unsafe.Pointer(packet.StartAtOffset(uintptr(i)))) = *(*uint8)(unsafe.Pointer(packet.StartAtOffset(uintptr(i + length))))
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
		*(*byte)(packet.StartAtOffset(uintptr(start + i))) = bytes[i]
	}
	return true
}

// NewPacket shouldn't be used for performance critical allocations.
// Allocate mbufs one by one is very inefficient.
// FastGenerate or copy functions give developer a packet from previously bulk allocated set
// Should be used only for testing or single events like ARP or ICMP answers
func NewPacket() (*Packet, error) {
	var mb uintptr
	if err := low.AllocateMbuf(&mb, nonPerfMempool); err != nil {
		return nil, err
	}
	pkt := ExtractPacket(mb)
	return pkt, nil
}

// SendPacket immidiately sends packet to specified port via calling C function.
// Packet is freed. Function return true if packet was actually sent.
// Port should be initialized. Packet is sent to zero queue (is always present).
// Sending simultaneously to one port is permitted in DPDK.
// Is very inefficient.
// Should be used only for testing or single events like ARP or ICMP answers
func (p *Packet) SendPacket(port uint16) bool {
	return low.DirectSend(p.CMbuf, port)
}

// SetNonPerfMempool sets default mempool for non performance critical allocations.
// Shouldn't be called by user
func SetNonPerfMempool(m *low.Mempool) {
	nonPerfMempool = m
}

type LPM struct {
	tbl24 *([types.MaxLength]types.IPv4Address)
	tbl8  *([types.MaxLength]types.IPv4Address)
	lpm   unsafe.Pointer //C.struct_rte_lpm
}

// CreateLPM creates longest prefix match structure with given name at given socket
// maxRules - maximum number of LPM rules inside table, numberTbl8 - maximum number
// of rules with mask length more than 24 bits
// LPM is stored in C management memory - no garbage collectors there. You should use
// Free function after working with it.
func CreateLPM(name string, socket uint8, maxRules uint32, numberTbl8 uint32) *LPM {
	lpm := new(LPM)
	lpm.lpm = low.CreateLPM(name, socket, maxRules, numberTbl8, unsafe.Pointer(&lpm.tbl24), unsafe.Pointer(&lpm.tbl8))
	return lpm
}

// Lookup looks for given ip inside LPM table. If ip was
// matched with LPM rule true is returned and nextHop contains
// next hop identifier for this rule. Else false is returned.
// Heavily based on DPDK rte_lpm_lookup with constants from there
// No error checking (lpm == NULL or nextHop == NULL) due to performance
// User should check it manually
func (lpm *LPM) Lookup(ip types.IPv4Address, nextHop *types.IPv4Address) bool {
	tbl24_index := ip >> 8
	tbl_entry := (*lpm.tbl24)[tbl24_index] // Copy tbl24 entry

	if tbl_entry&low.RteLpmValidExtEntryBitmask == low.RteLpmValidExtEntryBitmask {
		// Copy tbl8 entry (only if needed)
		tbl8_index := (ip & 0x000000FF) + ((tbl_entry & 0x00FFFFFF) * low.RteLpmTbl8GroupNumEntries)
		tbl_entry = (*lpm.tbl8)[tbl8_index]
	}

	if tbl_entry&low.RteLpmLookupSuccess != 0 {
		*nextHop = tbl_entry & 0x00FFFFFF
		return true
	}
	return false
}

// Add adds longest prefix match rule with specified ip, depth and nextHop
// inside LPM table. Returns 0 if success and negative value otherwise
func (lpm *LPM) Add(ip types.IPv4Address, depth uint8, nextHop types.IPv4Address) int {
	return low.AddLPMRule(lpm.lpm, ip, depth, nextHop)
}

// Delete removes longest prefix match rule with diven ip and depth from
// LPM table. Returns 0 if success and negative value otherwise
func (lpm *LPM) Delete(ip types.IPv4Address, depth uint8) int {
	return low.DeleteLPMRule(lpm.lpm, ip, depth)
}

// Free frees LPM C management memory
func (lpm *LPM) Free() {
	low.FreeLPM(lpm.lpm)
}

// GetPacketOffloadFlags returns ol_flags field of packet mbuf
func (pkt *Packet) GetPacketOffloadFlags() uint64 {
	return low.GetPacketOffloadFlags(pkt.CMbuf)
}

// GetPacketTimestamp returns timestamp field of packet mbuf. Check
// that flag PKT_RX_TIMESTAMP (1ULL << 17) is set in value returned by
// GetPacketOffloadFlags.
func (pkt *Packet) GetPacketTimestamp() uint64 {
	return low.GetPacketTimestamp(pkt.CMbuf)
}
