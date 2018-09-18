// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
)

func (port *ipPort) handleIPv6NeighborDiscovery(pkt *packet.Packet) uint {
	icmp := pkt.GetICMPNoCheck()
	if icmp.Type == common.ICMPv6NeighborSolicitation {
		// If there is KNI interface, forward all of this here
		if port.KNIName != "" {
			return dirKNI
		}
		pkt.ParseL7(common.ICMPv6Number)
		msg := pkt.GetICMPv6NeighborSolicitationMessage()
		if msg.TargetAddr != port.Subnet6.Addr {
			return dirDROP
		}
		option := pkt.GetICMPv6NDSourceLinkLayerAddressOption(packet.ICMPv6NeighborSolicitationMessageSize)
		if option != nil && option.Type == packet.ICMPv6NDSourceLinkLayerAddress {
			answerPacket, err := packet.NewPacket()
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			packet.GeneratePacketFromByte(answerPacket, pkt.GetRawPacketBytes())

			// Fill up L2
			answerPacket.ParseL3CheckVLAN()
			answerPacket.Ether.DAddr = answerPacket.Ether.SAddr
			answerPacket.Ether.SAddr = port.SrcMACAddress

			// Fill up L3
			ipv6 := answerPacket.GetIPv6NoCheck()
			ipv6.DstAddr = ipv6.SrcAddr
			ipv6.SrcAddr = port.Subnet6.Addr

			// Fill up L4
			answerPacket.ParseL4ForIPv6()
			icmp := answerPacket.GetICMPNoCheck()
			icmp.Type = common.ICMPv6NeighborAdvertisement
			icmp.Identifier = packet.SwapBytesUint16(packet.ICMPv6NDSolicitedFlag | packet.ICMPv6NDOverrideFlag)
			icmp.SeqNum = 0

			// Fill up L7
			answerPacket.ParseL7(common.ICMPv6Number)
			msg := answerPacket.GetICMPv6NeighborAdvertisementMessage()
			msg.TargetAddr = port.Subnet6.Addr
			option := answerPacket.GetICMPv6NDTargetLinkLayerAddressOption(packet.ICMPv6NeighborAdvertisementMessageSize)
			option.Type = packet.ICMPv6NDTargetLinkLayerAddress
			option.LinkLayerAddress = port.SrcMACAddress

			vlan := pkt.GetVLAN()
			if vlan != nil {
				answerPacket.AddVLANTag(packet.SwapBytesUint16(vlan.TCI))
			}

			setIPv6ICMPChecksum(answerPacket, !NoCalculateChecksum, !NoHWTXChecksum)
			port.dumpPacket(answerPacket, dirSEND)
			answerPacket.SendPacket(port.Index)
		}
	} else if icmp.Type == common.ICMPv6NeighborAdvertisement {
		pkt.ParseL7(common.ICMPv6Number)
		msg := pkt.GetICMPv6NeighborAdvertisementMessage()
		option := pkt.GetICMPv6NDTargetLinkLayerAddressOption(packet.ICMPv6NeighborAdvertisementMessageSize)
		if option != nil && option.Type == packet.ICMPv6NDTargetLinkLayerAddress {
			port.arpTable.Store(msg.TargetAddr, option.LinkLayerAddress)
		}

		if port.KNIName != "" {
			return dirKNI
		}
	} else {
		return dirSEND
	}

	return dirDROP
}
