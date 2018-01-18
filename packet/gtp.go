// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file highly assumes that all packets in each particular situation
// will have the same structure. Parsing, Encapsulating, Decapsulating
// functions are base variants without any checkings which can be
// painlessly changed for exact situation.

package packet

import (
	"fmt"
	"unsafe"

	. "github.com/intel-go/yanff/common"
)

// GTPv1-U and GTPv1-C
type GTPHdr struct {
	HeaderType          uint8 // version, protocol type, extension header/sequence number/N-PDU flags
	MessageType         uint8
	MessageLength       uint16
	TEID                uint32
	SequenceNumber      uint16 // this is valid only with sequence number flag
	NPDUNumber          uint8  // this is valid only with N-PDU flag
	NextExtensionHeader uint8  // this is valid only with exatension header flag
}

// TODO current support of GTP-U: only two extension headers
// NextExtensionHeader values
const (
	NoExtensionHeaders             = 0x00
	UDPPortExtensionHeader         = 0x40
	PDCP_PDU_NumberExtensionHeader = 0xc0
)

type UDPPort struct {
	Lenght              uint8 // in 4 octets, here always 0x01
	UDPPortNumber       uint16
	NextExtensionHeader uint8
}

type PDCP_PDU_Number struct {
	Length              uint8 // in 4 octets, here always 0x01
	PDCP_PDU_Number_1   uint8
	PDCP_PDU_Number_2   uint8
	NextExtensionHeader uint8
}

// TODO for GTP-U only
// MessageType values
const (
	// Signalling messages: path management
	EchoRequest                           = 1
	EchoResponse                          = 2
	SupportedExtensionHeadersNotification = 31
	// Signalling messages: tunnel management
	ErrorIndication = 26
	EndMarker       = 254
	// G-PDU message = encapsulated user data
	G_PDU = 255
)

// TODO Add "Information Element@ constants

func (hdr *GTPHdr) String() string {
	hType := "GTPv1"
	hTypeType := "GTP"
	if hdr.HeaderType&0xe0 != 1 {
		hType = "not GTPv1" // other versions are not supported
	}
	if hdr.HeaderType&0x10 == 0 {
		hTypeType = "GTP'"
	}
	min := fmt.Sprintf(`%s (%s): Message type: %d, Message length: %d, TEID: %d`, hTypeType, hType,
		hdr.MessageType, SwapBytesUint16(hdr.MessageLength), SwapBytesUint32(hdr.TEID))
	if hdr.HeaderType&0x02 != 0 {
		min += fmt.Sprintf(`, Sequence number %d`, SwapBytesUint16(hdr.SequenceNumber))
	}
	if hdr.HeaderType&0x01 != 0 {
		min += fmt.Sprintf(`, N-PDU number %d`, hdr.NPDUNumber)
	}
	if hdr.HeaderType&0x04 != 0 {
		min += fmt.Sprintf(`, N-PDU number %d`, hdr.NextExtensionHeader)
		// TODO add dumping of all extension headers
	}
	return min
}

// GetGTP assumes that packet is already parsed. Returns GTP header as payload after L4 header
func (packet *Packet) GetGTP() *GTPHdr {
	return (*GTPHdr)(packet.Data)
}

// GTPIPv4FastParsing assumes that nothing was parsed, however packet has ether->IPv4->UDP->GTP->payload data structure
// with standart IPv4 header size. Returns GTP header
func (packet *Packet) GTPIPv4FastParsing() *GTPHdr {
	return (*GTPHdr)(unsafe.Pointer(uintptr(packet.unparsed()) + IPv4MinLen + UDPLen))
}

// GTPIPv4AllParsing assumes that nothing was parsed, however packet has ether->IPv4->UDP->GTP->payload data structure
// Returns GTP header, fills L3, L4 and Data packet fields
func (packet *Packet) GTPIPv4AllParsing() *GTPHdr {
	packet.ParseL3()
	packet.ParseL4ForIPv4()
	packet.ParseL7(UDPNumber)
	return packet.GetGTP()
}

// EncapsulateIPv4GTP assumes that user wants to build ether->IPv4->UDP->GTP->payload data structure
// with standart IPv4 header size. It is also assumed that payload type is IPv4, so no etherType changes are needed
func (packet *Packet) EncapsulateIPv4GTP(TEID uint32) bool {
	if !packet.EncapsulateHead(EtherLen, IPv4MinLen+UDPLen+GTPMinLen) {
		return false
	}
	gtp := (*GTPHdr)(unsafe.Pointer(uintptr(packet.unparsed()) + IPv4MinLen + UDPLen))
	gtp.HeaderType = 0x30   // 001 - GTPv1, 1 - not GTP', 0 - reserved, 000 - no optional fields
	gtp.MessageType = G_PDU // encapsulated user message
	gtp.MessageLength = 0   // Just 8 byte header, no additions TODO no user data is calculated?
	gtp.TEID = SwapBytesUint32(TEID)
	return true
	// Developer can use standart parsing functions after this function
	// to fill new outer IPv4 and UDP protocols
}

// DecapsulateIPv4GTP assumes that user has etherNet->IPv4->UDP->GTP->payload data structure
// with standart IPv4 header size and wants to leave only ether->payload part
// It is also assumed that payload is encapsulated IPv4 datagram, so no etherType changes are needed
func (packet *Packet) DecapsulateIPv4GTP() bool {
	// No checking to extension headers. Assume GTP length = 8
	if !packet.DecapsulateHead(EtherLen, IPv4MinLen+UDPLen+GTPMinLen) {
		return false
	}
	return true
	// Developer can use standart parsing functions after this function
	// to check inner protocol stack after decapsulation
}
