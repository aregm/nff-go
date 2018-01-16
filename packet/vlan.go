// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"fmt"
	"unsafe"

	. "github.com/intel-go/yanff/common"
)

// VLANHdr 802.1Q VLAN header. We interpret it as an addition after
// EtherHdr structure, so it contains actual frame EtherType after TCI
// while TPID=0x8100 is present in EtherHdr.
type VLANHdr struct {
	TCI       uint16 // Tag control information. Contains PCP, DEI and VID bit-fields
	EtherType uint16 // Real EtherType instead of VLANNumber in EtherHdr.EtherType
}

func (hdr *VLANHdr) String() string {
	return fmt.Sprintf(`L2 VLAN:
TCI: 0x%02x (priority: %d, drop %d, ID: %d)
EtherType: 0x%02x`, SwapBytesUint16(hdr.TCI), byte(SwapBytesUint16(hdr.TCI)>>13),
		(SwapBytesUint16(hdr.TCI)>>12)&1, SwapBytesUint16(hdr.TCI)&0xfff, SwapBytesUint16(hdr.EtherType))
}

// GetVLANTagIdentifier returns VID (12 bits of VLAN tag from VLAN header).
func (hdr *VLANHdr) GetVLANTagIdentifier() uint16 {
	return SwapBytesUint16(hdr.TCI) & 0x0fff
}

// SetVLANTagIdentifier sets VID (12 bits of VLAN tag to specified value).
func (hdr *VLANHdr) SetVLANTagIdentifier(tag uint16) {
	hdr.TCI = SwapBytesUint16((SwapBytesUint16(hdr.TCI) & 0xf000) | (tag & 0x0fff))
}

// GetVLAN returns VLAN header pointer if it is present in the packet.
func (packet *Packet) GetVLAN() *VLANHdr {
	if packet.Ether.EtherType == SwapBytesUint16(VLANNumber) {
		return (*VLANHdr)(unsafe.Pointer(packet.unparsed()))
	}
	return nil
}

// GetVLANNoCheck casts pointer to memory right after Ethernet header
// to VLANHdr type.
func (packet *Packet) GetVLANNoCheck() *VLANHdr {
	return (*VLANHdr)(unsafe.Pointer(packet.unparsed()))
}

// GetEtherType correctly returns EtherType from Ethernet header or
// VLAN header.
func (packet *Packet) GetEtherType() uint16 {
	if packet.Ether.EtherType == SwapBytesUint16(VLANNumber) {
		vptr := packet.unparsed()
		vhdr := (*VLANHdr)(unsafe.Pointer(vptr))
		return SwapBytesUint16(vhdr.EtherType)
	}
	return SwapBytesUint16(packet.Ether.EtherType)
}

// ParseL3CheckVLAN set pointer to start of L3 header taking possible
// presence of VLAN header into account.
func (packet *Packet) ParseL3CheckVLAN() *VLANHdr {
	ptr := packet.unparsed()
	if packet.Ether.EtherType == SwapBytesUint16(VLANNumber) {
		packet.L3 = unsafe.Pointer(uintptr(ptr) + VLANLen)
		return (*VLANHdr)(ptr)
	}
	packet.L3 = ptr
	return nil
}

// GetIPv4CheckVLAN ensures if EtherType is IPv4 and casts L3 pointer
// to IPv4Hdr type. VLAN presence is checked if necessary.
func (packet *Packet) GetIPv4CheckVLAN() *IPv4Hdr {
	if packet.GetEtherType() == IPV4Number {
		return (*IPv4Hdr)(packet.L3)
	}
	return nil
}

// GetARPCheckVLAN ensures if EtherType is ARP and casts L3 pointer to
// ARPHdr type. VLAN presence is checked if necessary.
func (packet *Packet) GetARPCheckVLAN() *ARPHdr {
	if packet.GetEtherType() == ARPNumber {
		return (*ARPHdr)(packet.L3)
	}
	return nil
}

// GetIPv6CheckVLAN ensures if EtherType is IPv6 and cast L3 pointer
// to IPv6Hdr type. VLAN presence is checked if necessary.
func (packet *Packet) GetIPv6CheckVLAN() *IPv6Hdr {
	if packet.GetEtherType() == IPV6Number {
		return (*IPv6Hdr)(packet.L3)
	}
	return nil
}

// ParseAllKnownL3CheckVLAN parses L3 field and returns pointers to parsed
// headers taking possible presence of VLAN header into account.
func (packet *Packet) ParseAllKnownL3CheckVLAN() (*IPv4Hdr, *IPv6Hdr, *ARPHdr) {
	packet.ParseL3CheckVLAN()
	if packet.GetIPv4CheckVLAN() != nil {
		return packet.GetIPv4NoCheck(), nil, nil
	} else if packet.GetIPv6CheckVLAN() != nil {
		return nil, packet.GetIPv6NoCheck(), nil
	} else if packet.GetARPCheckVLAN() != nil {
		return nil, nil, packet.GetARPNoCheck()
	}
	return nil, nil, nil
}

// AddVLANTag increases size of packet on VLANLen and adds 802.1Q VLAN header
// after Ether header, tag is a tag control information. Returns false if error.
func (packet *Packet) AddVLANTag(tag uint16) bool {
	// We add vlanTag place two bytes before ending of ethernet.
	// VLANhdr.EtherType will automatically be correct and equal to previous ether.etherType
	if !packet.EncapsulateHead(EtherLen-2, VLANLen) {
		return false
	}
	vhdr := (*VLANHdr)(unsafe.Pointer(packet.unparsed()))
	// EncapsulateHead function has moved pointer to EtherType,
	// so the following line is correct. L3 stayed at the same place.
	packet.Ether.EtherType = SwapBytesUint16(VLANNumber)
	vhdr.TCI = SwapBytesUint16(tag)
	return true
}

// RemoveVLANTag decreases size of packet on VLANLen
func (packet *Packet) RemoveVLANTag() bool {
	// We want to remove 8100 etherType and remain actual "next" Exther type
	// so we need to remove 4 bytes starting 2 bytes earlier than VLANtag
	if !packet.DecapsulateHead(EtherLen-2, VLANLen) {
		return false
	}
	return true
}
