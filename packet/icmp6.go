// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"unsafe"

	"github.com/intel-go/nff-go/common"
)

const (
	ICMPv6NDSourceLinkLayerAddress uint8 = 1
	ICMPv6NDTargetLinkLayerAddress uint8 = 2
	ICMPv6NDPrefixInformation      uint8 = 3
	ICMPv6NDRedirectedHeader       uint8 = 4
	ICMPv6NDMTU                    uint8 = 5

	ICMPv6NeighborSolicitationMessageSize  uint = 16
	ICMPv6NeighborAdvertisementMessageSize uint = 16

	ICMPv6RNDouterFlag    uint16 = 0x8000
	ICMPv6NDSolicitedFlag uint16 = 0x4000
	ICMPv6NDOverrideFlag  uint16 = 0x2000
)

type ICMPv6NDSourceLinkLayerAddressOption struct {
	Type             uint8
	Length           uint8
	LinkLayerAddress [common.EtherAddrLen]uint8
}

type ICMPv6NDTargetLinkLayerAddressOption struct {
	Type             uint8
	Length           uint8
	LinkLayerAddress [common.EtherAddrLen]uint8
}

type ICMPv6NDPrefixInformationOption struct {
	Type              uint8
	Length            uint8
	PrefixLength      uint8
	LAFlags           uint8
	ValidLifetime     uint32
	PreferredLifetime uint32
	Reserved2         uint32
	Prefix            [common.IPv6AddrLen]uint8
}

type ICMPv6NDRedirectedHeaderOption struct {
	Type     uint8
	Length   uint8
	Reserved uint32
}

type ICMPv6NDMTUOption struct {
	Type   uint8
	Length uint8
	MTU    uint32
}

type ICMPv6NeighborSolicitationMessage struct {
	TargetAddr [common.IPv6AddrLen]uint8
}

type ICMPv6NeighborAdvertisementMessage struct {
	TargetAddr [common.IPv6AddrLen]uint8
}

// GetICMPv6NeighborSolicitationMessage returns pointer to ICMPv6
// Neighbor Solicitation message buffer. It should be called after
// packet.Data field is initialized with ParseL7 or ParseData calls.
func (packet *Packet) GetICMPv6NeighborSolicitationMessage() *ICMPv6NeighborSolicitationMessage {
	return (*ICMPv6NeighborSolicitationMessage)(packet.Data)
}

// GetICMPv6NeighborAdvertisementMessage returns pointer to ICMPv6
// Neighbor Solicitation message buffer. It should be called after
// packet.Data field is initialized with ParseL7 or ParseData calls.
func (packet *Packet) GetICMPv6NeighborAdvertisementMessage() *ICMPv6NeighborAdvertisementMessage {
	return (*ICMPv6NeighborAdvertisementMessage)(packet.Data)
}

// checkEnoughSpace returns true if there are more than space bytes in
// packet and false if there are less than or equal bytes than space.
func (packet *Packet) checkEnoughSpace(space uint) bool {
	pktStartAddr := packet.StartAtOffset(0)
	hdrsLen := int64(uintptr(packet.Data) - uintptr(pktStartAddr))
	packetLength := int64(packet.GetPacketSegmentLen())
	dataLength := packetLength - hdrsLen - int64(space)
	return dataLength > 0
}

// GetICMPv6NDSourceLinkLayerAddressOption returns Neighbor Discovery
// Source Link Layer option for an ICMPv6 message packet following a
// message of length msgLength. If packet is not long enough to
// contain this option, nil is returned.
func (packet *Packet) GetICMPv6NDSourceLinkLayerAddressOption(msgLength uint) *ICMPv6NDSourceLinkLayerAddressOption {
	if packet.checkEnoughSpace(msgLength) {
		return (*ICMPv6NDSourceLinkLayerAddressOption)(unsafe.Pointer(uintptr(packet.Data) + uintptr(msgLength)))
	}
	return nil
}

// GetICMPv6NDTargetLinkLayerAddressOption returns Neighbor Discovery
// Target Link Layer option for an ICMPv6 message packet following a
// message of length msgLength. If packet is not long enough to
// contain this option, nil is returned.
func (packet *Packet) GetICMPv6NDTargetLinkLayerAddressOption(msgLength uint) *ICMPv6NDSourceLinkLayerAddressOption {
	if packet.checkEnoughSpace(msgLength) {
		return (*ICMPv6NDSourceLinkLayerAddressOption)(unsafe.Pointer(uintptr(packet.Data) + uintptr(msgLength)))
	}
	return nil
}
