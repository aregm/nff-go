// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
)

func (port *ipPort) handleARP(pkt *packet.Packet) uint {
	arp := pkt.GetARPNoCheck()

	if packet.SwapBytesUint16(arp.Operation) != packet.ARPRequest {
		if packet.SwapBytesUint16(arp.Operation) == packet.ARPReply {
			ipv4 := packet.SwapBytesUint32(packet.ArrayToIPv4(arp.SPA))
			port.arpTable.Store(ipv4, arp.SHA)
		}
		if port.KNIName != "" {
			return dirKNI
		}
		return dirDROP
	}

	// If there is a KNI interface, direct all ARP traffic to it
	if port.KNIName != "" {
		return dirKNI
	}

	// Check that someone is asking about MAC of my IP address and HW
	// address is blank in request
	if packet.BytesToIPv4(arp.TPA[0], arp.TPA[1], arp.TPA[2], arp.TPA[3]) != packet.SwapBytesUint32(port.Subnet.Addr) {
		println("Warning! Got an ARP packet with target IPv4 address", StringIPv4Array(arp.TPA),
			"different from IPv4 address on interface. Should be", StringIPv4Int(port.Subnet.Addr),
			". ARP request ignored.")
		return dirDROP
	}
	if arp.THA != [common.EtherAddrLen]byte{} {
		println("Warning! Got an ARP packet with non-zero MAC address", StringMAC(arp.THA),
			". ARP request ignored.")
		return dirDROP
	}

	// Prepare an answer to this request
	answerPacket, err := packet.NewPacket()
	if err != nil {
		common.LogFatal(common.Debug, err)
	}

	packet.InitARPReplyPacket(answerPacket, port.SrcMACAddress, arp.SHA, packet.ArrayToIPv4(arp.TPA), packet.ArrayToIPv4(arp.SPA))
	vlan := pkt.GetVLAN()
	if vlan != nil {
		answerPacket.AddVLANTag(packet.SwapBytesUint16(vlan.TCI))
	}

	port.dumpPacket(answerPacket, dirSEND)
	answerPacket.SendPacket(port.Index)

	return dirDROP
}

func (port *ipPort) getMACForIPv4(ip uint32) (macAddress, bool) {
	v, found := port.arpTable.Load(ip)
	if found {
		return macAddress(v.([common.EtherAddrLen]byte)), true
	}
	port.sendARPRequest(ip)
	return macAddress{}, false
}

func (port *ipPort) sendARPRequest(ip uint32) {
	requestPacket, err := packet.NewPacket()
	if err != nil {
		common.LogFatal(common.Debug, err)
	}

	packet.InitARPRequestPacket(requestPacket, port.SrcMACAddress,
		packet.SwapBytesUint32(port.Subnet.Addr), packet.SwapBytesUint32(ip))
	if port.Vlan != 0 {
		requestPacket.AddVLANTag(port.Vlan)
	}

	port.dumpPacket(requestPacket, dirSEND)
	requestPacket.SendPacket(port.Index)
}
