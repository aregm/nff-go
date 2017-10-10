// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"fmt"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
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
	SPA       uint32                     // Sender protocol address (sender IPv4 address)
	THA       [common.EtherAddrLen]uint8 // Target hardware address (target MAC address)
	TPA       uint32                     // Target protocol address (target IPv4 address)
}

// ARP protocol operations
const (
	ARPRequest  = 1
	ARPReply    = 2
	RARPRequest = 3
	RARPReply   = 4
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
		byte(hdr.SPA), byte(hdr.SPA>>8), byte(hdr.SPA>>16), byte(hdr.SPA>>24),
		hdr.THA[0], hdr.THA[1], hdr.THA[2], hdr.THA[3], hdr.THA[4], hdr.THA[5],
		byte(hdr.TPA), byte(hdr.TPA>>8), byte(hdr.TPA>>16), byte(hdr.TPA>>24))
}

// InitEmptyARPPacket initializes empty ARP packet
func InitEmptyARPPacket(packet *Packet) bool {
	var bufSize uint = common.EtherLen + common.ARPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		common.LogWarning(common.Debug, "InitEmptyARPPacket: Cannot append mbuf")
		return false
	}

	packet.Ether.EtherType = SwapBytesUint16(common.ARPNumber)
	return true
}

// InitARPRequestPacket initialize ARP request packet for IPv4
// protocol request with broadcast (zero) for THA (Target HW
// address). SHA and SPA specify sender MAC and IP addresses, TPA
// specifies IP address for host which request is sent
// for. Destionation MAC address is L2 Ethernet header is set to
// FF:FF:FF:FF:FF:FF (broadcast) and source address is set to SHA.
func InitARPRequestPacket(packet *Packet, SHA [common.EtherAddrLen]uint8, SPA, TPA uint32) bool {
	var bufSize uint = common.EtherLen + common.ARPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		common.LogWarning(common.Debug, "InitARPRequestPacket: Cannot append mbuf")
		return false
	}

	packet.Ether.EtherType = SwapBytesUint16(common.ARPNumber)
	packet.Ether.DAddr = [common.EtherAddrLen]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	packet.Ether.SAddr = SHA

	packet.ParseL3()
	arp := packet.GetARP()
	arp.HType = SwapBytesUint16(1)
	arp.PType = SwapBytesUint16(common.IPV4Number)
	arp.HLen = 6
	arp.PLen = 4
	arp.Operation = SwapBytesUint16(ARPRequest)
	arp.SHA = SHA
	arp.SPA = SPA
	arp.THA = [common.EtherAddrLen]uint8{}
	arp.TPA = TPA
	return true
}

// InitARPReplyPacket initialize ARP reply packet for IPv4
// protocol. SHA and SPA specify sender MAC and IP addresses, THA and
// TPA specify target MAC and IP addresses. Destionation MAC address
// is L2 Ethernet header is set to THA and source address is set to
// SHA.
func InitARPReplyPacket(packet *Packet, SHA, THA [common.EtherAddrLen]uint8, SPA, TPA uint32) bool {
	var bufSize uint = common.EtherLen + common.ARPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		common.LogWarning(common.Debug, "InitGARPAnnouncementReplyPacket: Cannot append mbuf")
		return false
	}

	packet.Ether.EtherType = SwapBytesUint16(common.ARPNumber)
	packet.Ether.DAddr = THA
	packet.Ether.SAddr = SHA

	packet.ParseL3()
	arp := packet.GetARP()
	arp.HType = SwapBytesUint16(1)
	arp.PType = SwapBytesUint16(common.IPV4Number)
	arp.HLen = 6
	arp.PLen = 4
	arp.Operation = SwapBytesUint16(ARPReply)
	arp.SHA = SHA
	arp.SPA = SPA
	arp.THA = THA
	arp.TPA = TPA
	return true
}

// InitGARPAnnouncementRequestPacket initialize gratuitous ARP request
// (preferred over reply) packet (ARP announcement) for IPv4 protocol
// request with broadcast (zero) for THA (Target HW address). SHA and
// SPA specify sender MAC and IP addresses, TPA is set to the value of
// SPA. Destionation MAC address is L2 Ethernet header is set to
// FF:FF:FF:FF:FF:FF (broadcast) and source address is set to SHA.
func InitGARPAnnouncementRequestPacket(packet *Packet, SHA [common.EtherAddrLen]uint8, SPA uint32) bool {
	var bufSize uint = common.EtherLen + common.ARPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		common.LogWarning(common.Debug, "InitGARPAnnouncementRequestPacket: Cannot append mbuf")
		return false
	}

	packet.Ether.EtherType = SwapBytesUint16(common.ARPNumber)
	packet.Ether.DAddr = [common.EtherAddrLen]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	packet.Ether.SAddr = SHA

	packet.ParseL3()
	arp := packet.GetARP()
	arp.HType = SwapBytesUint16(1)
	arp.PType = SwapBytesUint16(common.IPV4Number)
	arp.HLen = 6
	arp.PLen = 4
	arp.Operation = SwapBytesUint16(ARPRequest)
	arp.SHA = SHA
	arp.SPA = SPA
	arp.THA = [common.EtherAddrLen]uint8{}
	arp.TPA = SPA
	return true
}

// InitGARPAnnouncementReplyPacket initialize gratuitous ARP reply
// packet (ARP announcement) for IPv4 protocol. SHA and SPA specify
// sender MAC and IP addresses, TPA is set to the value of SPA and THA
// to the value of SHA. Destionation MAC address is L2 Ethernet header
// is set to FF:FF:FF:FF:FF:FF (broadcast) and source address is set
// to SHA.
func InitGARPAnnouncementReplyPacket(packet *Packet, SHA [common.EtherAddrLen]uint8, SPA uint32) bool {
	var bufSize uint = common.EtherLen + common.ARPLen
	if low.AppendMbuf(packet.CMbuf, bufSize) == false {
		common.LogWarning(common.Debug, "InitGARPAnnouncementReplyPacket: Cannot append mbuf")
		return false
	}

	packet.Ether.EtherType = SwapBytesUint16(common.ARPNumber)
	packet.Ether.DAddr = [common.EtherAddrLen]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	packet.Ether.SAddr = SHA

	packet.ParseL3()
	arp := packet.GetARP()
	arp.HType = SwapBytesUint16(1)
	arp.PType = SwapBytesUint16(common.IPV4Number)
	arp.HLen = 6
	arp.PLen = 4
	arp.Operation = SwapBytesUint16(ARPReply)
	arp.SHA = SHA
	arp.SPA = SPA
	arp.THA = SHA
	arp.TPA = SPA
	return true
}
