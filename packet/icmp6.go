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

	ICMPv6RNDouterFlag    uint16 = 0x8000
	ICMPv6NDSolicitedFlag uint16 = 0x4000
	ICMPv6NDOverrideFlag  uint16 = 0x2000

	ICMPv6NDMessageOptionUnitSize = 8
)

var (
	ipv6LinkLocalPrefix          = []uint8{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	ipv6LinkLocalMulticastPrefix = []uint8{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff}
	ipv6EtherMulticastPrefix     = []uint8{0x33, 0x33}

	ICMPv6NeighborSolicitationMessageSize    uint = uint(unsafe.Sizeof(ICMPv6NeighborSolicitationMessage{}))
	ICMPv6NeighborAdvertisementMessageSize   uint = uint(unsafe.Sizeof(ICMPv6NeighborAdvertisementMessage{}))
	ICMPv6NDSourceLinkLayerAddressOptionSize uint = uint(unsafe.Sizeof(ICMPv6NDSourceLinkLayerAddressOption{}))
	ICMPv6NDTargetLinkLayerAddressOptionSize uint = uint(unsafe.Sizeof(ICMPv6NDTargetLinkLayerAddressOption{}))
)

type ICMPv6NDSourceLinkLayerAddressOption struct {
	Type             uint8
	Length           uint8
	LinkLayerAddress common.MACAddress
}

type ICMPv6NDTargetLinkLayerAddressOption struct {
	Type             uint8
	Length           uint8
	LinkLayerAddress common.MACAddress
}

type ICMPv6NDPrefixInformationOption struct {
	Type              uint8
	Length            uint8
	PrefixLength      uint8
	LAFlags           uint8
	ValidLifetime     uint32
	PreferredLifetime uint32
	Reserved2         uint32
	Prefix            common.IPv6Address
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
	TargetAddr common.IPv6Address
}

type ICMPv6NeighborAdvertisementMessage struct {
	TargetAddr common.IPv6Address
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

// CalculateIPv6LinkLocalAddrForMAC generates IPv6 link local address
// based on interface MAC address.
func CalculateIPv6LinkLocalAddrForMAC(llAddr *common.IPv6Address, mac common.MACAddress) {
	copy((*llAddr)[:], ipv6LinkLocalPrefix)
	(*llAddr)[8] = mac[0] ^ 0x02
	(*llAddr)[9] = mac[1]
	(*llAddr)[10] = mac[2]
	(*llAddr)[11] = 0xff
	(*llAddr)[12] = 0xfe
	(*llAddr)[13] = mac[3]
	(*llAddr)[14] = mac[4]
	(*llAddr)[15] = mac[5]
}

// CalculateIPv6MulticastAddrForDstIP generates IPv6 multicast address
// that other hosts use to solicit its MAC address. This address is
// used as destination for all Neighbor Solicitation ICMPv6 messages
// and NAT should answer packets coming to it.
func CalculateIPv6MulticastAddrForDstIP(muticastAddr *common.IPv6Address, dstIP common.IPv6Address) {
	copy((*muticastAddr)[:], ipv6LinkLocalMulticastPrefix)
	(*muticastAddr)[13] = dstIP[13]
	(*muticastAddr)[14] = dstIP[14]
	(*muticastAddr)[15] = dstIP[15]
}

func CalculateIPv6BroadcastMACForDstMulticastIP(dstMAC *common.MACAddress, dstIP common.IPv6Address) {
	copy((*dstMAC)[:], ipv6EtherMulticastPrefix)
	(*dstMAC)[2] = dstIP[12]
	(*dstMAC)[3] = dstIP[13]
	(*dstMAC)[4] = dstIP[14]
	(*dstMAC)[5] = dstIP[15]
}

// InitICMPv6NeighborSolicitationPacket allocates and initializes
// ICMPv6 Neighbor Solicitation request message packet with source MAC
// and IPv6 address and target IPv6 address.
func InitICMPv6NeighborSolicitationPacket(packet *Packet, srcMAC common.MACAddress, srcIP, dstIP common.IPv6Address) {
	InitEmptyIPv6ICMPPacket(packet, ICMPv6NeighborSolicitationMessageSize+ICMPv6NDSourceLinkLayerAddressOptionSize)

	var targetMulticastAddr common.IPv6Address
	CalculateIPv6MulticastAddrForDstIP(&targetMulticastAddr, dstIP)

	// Fill up L2
	CalculateIPv6BroadcastMACForDstMulticastIP(&packet.Ether.DAddr, targetMulticastAddr)
	packet.Ether.SAddr = srcMAC

	// Fill up L3
	ipv6 := packet.GetIPv6NoCheck()
	ipv6.DstAddr = targetMulticastAddr
	ipv6.SrcAddr = srcIP

	// Fill up L4
	icmp := packet.GetICMPNoCheck()
	icmp.Type = common.ICMPv6NeighborSolicitation
	icmp.Identifier = 0
	icmp.SeqNum = 0

	// Fill up L7
	packet.ParseL7(common.ICMPv6Number)
	msg := packet.GetICMPv6NeighborSolicitationMessage()
	msg.TargetAddr = dstIP
	option := packet.GetICMPv6NDSourceLinkLayerAddressOption(ICMPv6NeighborSolicitationMessageSize)
	option.Type = ICMPv6NDSourceLinkLayerAddress
	option.Length = uint8(ICMPv6NDSourceLinkLayerAddressOptionSize / ICMPv6NDMessageOptionUnitSize)
	option.LinkLayerAddress = srcMAC
}

// InitICMPv6NeighborAdvertisementPacket allocates and initializes
// ICMPv6 Neighbor Advertisement answer message packet with source MAC
// and IPv6 address and target IPv6 address.
func InitICMPv6NeighborAdvertisementPacket(packet *Packet, srcMAC, dstMAC common.MACAddress, srcIP, dstIP common.IPv6Address) {
	InitEmptyIPv6ICMPPacket(packet, ICMPv6NeighborAdvertisementMessageSize+ICMPv6NDTargetLinkLayerAddressOptionSize)

	// Fill up L2
	packet.Ether.DAddr = dstMAC
	packet.Ether.SAddr = srcMAC

	// Fill up L3
	ipv6 := packet.GetIPv6NoCheck()
	ipv6.DstAddr = dstIP
	ipv6.SrcAddr = srcIP

	// Fill up L4
	icmp := packet.GetICMPNoCheck()
	icmp.Type = common.ICMPv6NeighborAdvertisement
	icmp.Identifier = SwapBytesUint16(ICMPv6NDSolicitedFlag | ICMPv6NDOverrideFlag)
	icmp.SeqNum = 0

	// Fill up L7
	packet.ParseL7(common.ICMPv6Number)
	msg := packet.GetICMPv6NeighborAdvertisementMessage()
	msg.TargetAddr = srcIP
	option := packet.GetICMPv6NDTargetLinkLayerAddressOption(ICMPv6NeighborAdvertisementMessageSize)
	option.Type = ICMPv6NDTargetLinkLayerAddress
	option.Length = uint8(ICMPv6NDTargetLinkLayerAddressOptionSize / ICMPv6NDMessageOptionUnitSize)
	option.LinkLayerAddress = srcMAC
}
