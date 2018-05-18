// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"fmt"

	"github.com/intel-go/nff-go/common"
)

// ARPHdr is protocol structure used in Address Resolution Protocol
// for IPv4 to MAC mapping
type ARPHdr struct {
	HType     uint16                     // Hardware type, e.g. 1 for Ethernet
	PType     uint16                     // Protocol type, e.g. 0x0800 for IPv4
	HLen      uint8                      // Hardware address length, e.g. 6 for MAC length
	PLen      uint8                      // Protocol address length, e.g. 4 for IPv4 address length
	Operation uint16                     // Operation type, see ARP constants
	SHA       [common.EtherAddrLen]uint8 // Sender hardware address (sender MAC address)
	SPA       [common.IPv4AddrLen]uint8  // Sender protocol address (sender IPv4 address)
	// array is used to avoid alignment (compiler alignes uint32 on 4 bytes)
	THA [common.EtherAddrLen]uint8 // Target hardware address (target MAC address)
	TPA [common.IPv4AddrLen]uint8  // Target protocol address (target IPv4 address)
	// array is used to avoid alignment (compiler alignes uint32 on 4 bytes)
}

// ARP protocol operations
const (
	ARPRequest = 1
	ARPReply   = 2
)

func (hdr *ARPHdr) String() string {
	return fmt.Sprintf(`    L3 protocol: ARP\n
    HType: %d\n
    PType: %d\n
    HLen:  %d\n
    PLen:  %d\n
    Operation: %d\n
    Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n
    Sender IPv4 address: %d.%d.%d.%d\n
    Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n
    Target IPv4 address: %d.%d.%d.%d\n`,
		hdr.HType,
		hdr.PType,
		hdr.HLen,
		hdr.PLen,
		hdr.Operation,
		hdr.SHA[0], hdr.SHA[1], hdr.SHA[2], hdr.SHA[3], hdr.SHA[4], hdr.SHA[5],
		hdr.SPA[0], hdr.SPA[1], hdr.SPA[2], hdr.SPA[3],
		hdr.THA[0], hdr.THA[1], hdr.THA[2], hdr.THA[3], hdr.THA[4], hdr.THA[5],
		hdr.TPA[0], hdr.TPA[1], hdr.TPA[2], hdr.TPA[3])
}

// initARPCommonData allocates ARP packet, fills ether header and
// arp hrd, pro, hln, pln with values for ether and IPv4
func initARPCommonData(packet *Packet) bool {
	if InitEmptyARPPacket(packet) == false {
		return false
	}

	packet.ParseL3()
	arp := packet.GetARP()
	arp.HType = SwapBytesUint16(1)
	arp.PType = SwapBytesUint16(common.IPV4Number)
	arp.HLen = common.EtherAddrLen
	arp.PLen = common.IPv4AddrLen
	return true
}

// InitARPRequestPacket initialize ARP request packet for IPv4
// protocol request with broadcast (zero) for THA (Target HW
// address). SHA and SPA specify sender MAC and IP addresses, TPA
// specifies IP address for host which request is sent
// for. Destination MAC address in L2 Ethernet header is set to
// FF:FF:FF:FF:FF:FF (broadcast) and source address is set to SHA.
func InitARPRequestPacket(packet *Packet, SHA [common.EtherAddrLen]uint8, SPA, TPA uint32) bool {
	if !initARPCommonData(packet) {
		common.LogWarning(common.Debug, "InitARPRequestPacket: failed to fill common data")
		return false
	}
	packet.Ether.SAddr = SHA
	packet.Ether.DAddr = [common.EtherAddrLen]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	arp := packet.GetARP()
	arp.Operation = SwapBytesUint16(ARPRequest)
	arp.SHA = SHA
	arp.SPA = IPv4ToBytes(SPA)
	arp.THA = [common.EtherAddrLen]uint8{}
	arp.TPA = IPv4ToBytes(TPA)
	return true
}

// InitARPReplyPacket initialize ARP reply packet for IPv4
// protocol. SHA and SPA specify sender MAC and IP addresses, THA and
// TPA specify target MAC and IP addresses. Destination MAC address
// in L2 Ethernet header is set to THA and source address is set to
// SHA.
func InitARPReplyPacket(packet *Packet, SHA, THA [common.EtherAddrLen]uint8, SPA, TPA uint32) bool {
	if !initARPCommonData(packet) {
		common.LogWarning(common.Debug, "InitARPRequestPacket: failed to fill common data")
		return false
	}
	packet.Ether.SAddr = SHA
	packet.Ether.DAddr = THA
	arp := packet.GetARP()
	arp.Operation = SwapBytesUint16(ARPReply)
	arp.SHA = SHA
	arp.SPA = IPv4ToBytes(SPA)
	arp.THA = THA
	arp.TPA = IPv4ToBytes(TPA)
	return true
}

// InitGARPAnnouncementRequestPacket initialize gratuitous ARP request
// (preferred over reply) packet (ARP announcement) for IPv4 protocol
// request with broadcast (zero) for THA (Target HW address). SHA and
// SPA specify sender MAC and IP addresses, TPA is set to the value of
// SPA. Destination MAC address in L2 Ethernet header is set to
// FF:FF:FF:FF:FF:FF (broadcast) and source address is set to SHA.
func InitGARPAnnouncementRequestPacket(packet *Packet, SHA [common.EtherAddrLen]uint8, SPA uint32) bool {
	if !initARPCommonData(packet) {
		common.LogWarning(common.Debug, "InitARPRequestPacket: failed to fill common data")
		return false
	}
	packet.Ether.SAddr = SHA
	packet.Ether.DAddr = [common.EtherAddrLen]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	arp := packet.GetARP()
	arp.Operation = SwapBytesUint16(ARPRequest)
	arp.SHA = SHA
	arp.SPA = IPv4ToBytes(SPA)
	arp.THA = [common.EtherAddrLen]uint8{}
	arp.TPA = IPv4ToBytes(SPA)
	return true
}

// InitGARPAnnouncementReplyPacket initialize gratuitous ARP reply
// packet (ARP announcement) for IPv4 protocol. SHA and SPA specify
// sender MAC and IP addresses, TPA is set to the value of SPA and THA
// to zeroes (according to RFC 5227). Destination MAC address in L2 Ethernet header is set
// to FF:FF:FF:FF:FF:FF (broadcast) and source address is set
// to SHA.
func InitGARPAnnouncementReplyPacket(packet *Packet, SHA [common.EtherAddrLen]uint8, SPA uint32) bool {
	if !initARPCommonData(packet) {
		common.LogWarning(common.Debug, "InitARPRequestPacket: failed to fill common data")
		return false
	}
	packet.Ether.SAddr = SHA
	packet.Ether.DAddr = [common.EtherAddrLen]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	arp := packet.GetARP()
	arp.Operation = SwapBytesUint16(ARPReply)
	arp.SHA = SHA
	arp.SPA = IPv4ToBytes(SPA)
	arp.THA = [common.EtherAddrLen]uint8{}
	arp.TPA = IPv4ToBytes(SPA)
	return true
}
