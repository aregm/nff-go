// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"math"
)

// Max array length for type conversions
const MaxLength = math.MaxInt32

// Length of addresses.
const (
	EtherAddrLen = 6
	IPv4AddrLen  = 4
	IPv6AddrLen  = 16
)

// Supported EtherType for L2
const (
	IPV4Number = 0x0800
	ARPNumber  = 0x0806
	VLANNumber = 0x8100
	MPLSNumber = 0x8847
	IPV6Number = 0x86dd

	SwapIPV4Number = 0x0008
	SwapARPNumber  = 0x0608
	SwapVLANNumber = 0x0081
	SwapMPLSNumber = 0x4788
	SwapIPV6Number = 0xdd86
)

// Supported L4 types
const (
	ICMPNumber   = 0x01
	IPNumber     = 0x04
	TCPNumber    = 0x06
	UDPNumber    = 0x11
	GRENumber    = 0x2f
	ICMPv6Number = 0x3a
	NoNextHeader = 0x3b
)

// Supported ICMP Types
const (
	ICMPTypeEchoRequest         uint8 = 8
	ICMPTypeEchoResponse        uint8 = 0
	ICMPv6TypeEchoRequest       uint8 = 128
	ICMPv6TypeEchoResponse      uint8 = 129
	ICMPv6NeighborSolicitation  uint8 = 135
	ICMPv6NeighborAdvertisement uint8 = 136
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
	VLANLen    = 4
	MPLSLen    = 4
	IPv4MinLen = 20
	IPv6Len    = 40
	ICMPLen    = 8
	TCPMinLen  = 20
	UDPLen     = 8
	ARPLen     = 28
	GTPMinLen  = 8
	GRELen     = 4
)

const (
	TCPMinDataOffset = 0x50 // minimal tcp data offset
	IPv4VersionIhl   = 0x45 // IPv4, IHL = 5 (min header len)
	IPv6VtcFlow      = 0x60 // IPv6 version
)

// TCPFlags contains set TCP flags.
type TCPFlags uint8

// Constants for valuues of TCP flags.
const (
	TCPFlagFin = 0x01
	TCPFlagSyn = 0x02
	TCPFlagRst = 0x04
	TCPFlagPsh = 0x08
	TCPFlagAck = 0x10
	TCPFlagUrg = 0x20
	TCPFlagEce = 0x40
	TCPFlagCwr = 0x80
)
