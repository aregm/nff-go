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
	return fmt.Sprintf(`L2 VLAN:\n
TCI: 0x%02x (priority: %d, drop %d, ID: %d)\n
EtherType: 0x%02x\n`, hdr.TCI, byte(hdr.TCI>>13), (hdr.TCI>>12)&1, hdr.TCI&0xfff, hdr.EtherType)
}

// GetTag returns 12 bits of VLAN tag from VLAN header.
func (hdr *VLANHdr) GetTag() uint16 {
	return SwapBytesUint16(hdr.TCI) & 0xfff
}

// SetTag sets 12 bits of VLAN tag to specified value.
func (hdr *VLANHdr) SetTag(tag uint16) {
	hdr.TCI = (hdr.TCI & 0xf000) | SwapBytesUint16(tag & 0xfff)
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
		return vhdr.EtherType
	} else {
		return packet.Ether.EtherType
	}
}

// ParseL3CheckVLAN set pointer to start of L3 header taking possible
// presence of VLAN header into account.
func (packet *Packet) ParseL3CheckVLAN() *VLANHdr {
	ptr := packet.unparsed()

	if packet.Ether.EtherType == SwapBytesUint16(VLANNumber) {
		packet.L3 = unsafe.Pointer(ptr + VLANLen)
		return (*VLANHdr)(unsafe.Pointer(packet.unparsed()))
	}
	packet.L3 = unsafe.Pointer(ptr)
	return nil
}

// GetIPv4CheckVLAN ensures if EtherType is IPv4 and casts L3 pointer
// to IPv4Hdr type. VLAN presence is checked if necessary.
func (packet *Packet) GetIPv4CheckVLAN() *IPv4Hdr {
	if packet.GetEtherType() == SwapBytesUint16(IPV4Number) {
		return (*IPv4Hdr)(packet.L3)
	}
	return nil
}

// GetARPCheckVLAN ensures if EtherType is ARP and casts L3 pointer to
// ARPHdr type. VLAN presence is checked if necessary.
func (packet *Packet) GetARPCheckVLAN() *ARPHdr {
	if packet.GetEtherType() == SwapBytesUint16(ARPNumber) {
		return (*ARPHdr)(packet.L3)
	}
	return nil
}

// GetIPv6CheckVLAN ensures if EtherType is IPv6 and cast L3 pointer
// to IPv6Hdr type. VLAN presence is checked if necessary.
func (packet *Packet) GetIPv6CheckVLAN() *IPv6Hdr {
	if packet.GetEtherType() == SwapBytesUint16(IPV6Number) {
		return (*IPv6Hdr)(packet.L3)
	}
	return nil
}

// AddVLANTag increases size of packet on VLANLen and adds 802.1Q VLAN header
// after Ether header, tag is a tag control information. Returns false if error.
func (packet *Packet) AddVLANTag(tag uint16) bool {
	if !packet.EncapsulateHead(EtherLen, VLANLen) {
		return false
	}
	vhdr := (*VLANHdr)(unsafe.Pointer(packet.unparsed()))
	// EncapsulateHead function has moved pointer to EtherType,
	// so the following line is correct. L3 stayed at the same place.
	vhdr.EtherType = packet.Ether.EtherType
	packet.Ether.EtherType = SwapBytesUint16(VLANNumber)
	vhdr.TCI = SwapBytesUint16(tag)
	return true
}
