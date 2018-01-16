// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"fmt"
	"unsafe"

	. "github.com/intel-go/yanff/common"
)

type MPLSHdr struct {
	mpls uint32 // Label, Exp, S, TTL
}

func (hdr *MPLSHdr) String() string {
	return fmt.Sprintf(`MPLS: Label: %d, EXP: %d, S: %d TTL: %d`,
		SwapBytesUint32(hdr.mpls)>>12, (SwapBytesUint32(hdr.mpls)>>9)&0x00000007,
		(SwapBytesUint32(hdr.mpls)>>8)&1, SwapBytesUint32(hdr.mpls)&0x000000ff)
}

// GetMPLSLabel returns Label (20 first bits of MPLS header).
func (hdr *MPLSHdr) GetMPLSLabel() uint32 {
	return SwapBytesUint32(hdr.mpls) >> 12
}

// SetMPLSLabel sets Label (20 first bits of MPLS header to specified value).
func (hdr *MPLSHdr) SetMPLSLabel(tag uint32) {
	hdr.mpls = SwapBytesUint32((SwapBytesUint32(hdr.mpls) & 0xfff) | (tag << 12))
}

// GetMPLS returns MPLS header pointer if it is present in the packet.
func (packet *Packet) GetMPLS() *MPLSHdr {
	// MPLS shouldn't be used with VLAN tags, so we don't check any VLAN tags here
	if packet.Ether.EtherType == SwapBytesUint16(MPLSNumber) {
		return (*MPLSHdr)(unsafe.Pointer(packet.unparsed()))
	}
	return nil
}

// GetMPLSNoCheck casts pointer to memory right after Ethernet header
// to MPLSHdr type.
func (packet *Packet) GetMPLSNoCheck() *MPLSHdr {
	return (*MPLSHdr)(unsafe.Pointer(packet.unparsed()))
}

// ParseL3CheckMPLS set pointer to start of L3 header taking possible
// presence of MPLS header into account.
func (packet *Packet) ParseL3CheckMPLS() *MPLSHdr {
	ptr := packet.unparsed()
	// MPLS shouldn't be used with VLAN tags, so we don't check any VLAN tags here
	if packet.Ether.EtherType == SwapBytesUint16(MPLSNumber) {
		packet.L3 = unsafe.Pointer(uintptr(ptr) + MPLSLen)
		return (*MPLSHdr)(ptr)
	}
	packet.L3 = ptr
	return nil
}

// There are no "GetIPv4CheckMPLS, etc." functions here because
// mapping label to protocol ID is uniq for each label.

// AddMPLS increases size of packet on MPLSLen and adds MPLS header
// after Ether header, mpls is a whole MPLS header. Returns false if error.
func (packet *Packet) AddMPLS(mpls uint32) bool {
	if !packet.EncapsulateHead(EtherLen, MPLSLen) {
		return false
	}
	mhdr := (*MPLSHdr)(unsafe.Pointer(packet.unparsed()))
	// EncapsulateHead function has moved pointer to EtherType,
	// so the following line is correct. L3 stayed at the same place.
	packet.Ether.EtherType = SwapBytesUint16(MPLSNumber)
	mhdr.mpls = SwapBytesUint32(mpls)
	return true
}

// RemoveMPLS decreases size of packet on MPLSLen
// THIS FUNCTION DOESN'T SET ETHERTYPE!!! IT SHOULD BE SET ACCORDING TO LABEL!!!
// ETHERTYPE WILL REMAIN MPLS-LIKE = 0x8847
func (packet *Packet) RemoveMPLS() bool {
	if !packet.DecapsulateHead(EtherLen, MPLSLen) {
		return false
	}
	return true
}

// SetMPLSLabel sets Label (20 first bits of MPLS header to specified value).
func (hdr *MPLSHdr) DecreaseTTL() bool {
	newTime := SwapBytesUint32(hdr.mpls)&0x000000ff - 1
	if newTime == 0 {
		return false
	}
	hdr.mpls = SwapBytesUint32(SwapBytesUint32(hdr.mpls)&0xffffff00 | newTime)
	return true
}
