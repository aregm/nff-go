// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"time"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
)

func (port *ipPort) handleICMP(protocol uint8, pkt *packet.Packet, key interface{}) uint {
	// Check that received ICMP packet is addressed at this host. If
	// not, packet should be translated
	var requestCode uint8
	var packetSentToUs bool
	var packetSentToMulticast bool
	if protocol == common.ICMPNumber {
		if packet.SwapBytesUint32(pkt.GetIPv4NoCheck().DstAddr) == port.Subnet.Addr {
			packetSentToUs = true
		}
		requestCode = common.ICMPTypeEchoRequest
	} else {
		// If message is not targeted at NAT host, it is subject of
		// address translation
		ipv6 := pkt.GetIPv6NoCheck()
		if ipv6.DstAddr == port.Subnet6.Addr ||
			ipv6.DstAddr == port.Subnet6.llAddr {
			packetSentToUs = true
		} else if ipv6.DstAddr == port.Subnet6.multicastAddr ||
			ipv6.DstAddr == port.Subnet6.llMulticastAddr {
			packetSentToMulticast = true
		}
		requestCode = common.ICMPv6TypeEchoRequest
	}

	// Check IPv6 Neighbor Discovery first. If packet is handled, it
	// returns DROP or KNI, otherwise continue to process it.
	if packetSentToMulticast || (packetSentToUs && protocol == common.ICMPv6Number) {
		dir := port.handleIPv6NeighborDiscovery(pkt)
		if dir != dirSEND {
			return dir
		}
	}

	icmp := pkt.GetICMPNoCheck()

	// If there is KNI interface, direct all ICMP traffic which
	// doesn't have an active translation entry. It may happen only
	// for public->private translation when all packets are directed
	// to NAT public interface IP, so port.portmap exists because port
	// is public.
	if packetSentToUs && port.KNIName != "" {
		if key != nil {
			_, ok := port.translationTable[protocol].Load(key)
			if !ok || time.Since(port.getPortmap(protocol == common.ICMPv6Number, protocol)[icmp.Identifier].lastused) > connectionTimeout {
				return dirKNI
			}
		}
	}

	// If packet sent to us, check that it is ICMP echo request. NAT
	// does not support any other messages yet, so process them in
	// normal way. Maybe these are packets which should be passed
	// through translation.
	if !packetSentToUs || icmp.Type != requestCode || icmp.Code != 0 {
		return dirSEND
	}

	// Return a packet back to sender
	answerPacket, err := packet.NewPacket()
	if err != nil {
		common.LogFatal(common.Debug, err)
	}
	packet.GeneratePacketFromByte(answerPacket, pkt.GetRawPacketBytes())

	answerPacket.ParseL3CheckVLAN()
	if protocol == common.ICMPNumber {
		swapAddrIPv4(answerPacket)
		answerPacket.ParseL4ForIPv4()
		(answerPacket.GetICMPNoCheck()).Type = common.ICMPTypeEchoResponse
		setIPv4ICMPChecksum(answerPacket, !NoCalculateChecksum, !NoHWTXChecksum)
	} else {
		swapAddrIPv6(answerPacket)
		answerPacket.ParseL4ForIPv6()
		(answerPacket.GetICMPNoCheck()).Type = common.ICMPv6TypeEchoResponse
		setIPv6ICMPChecksum(answerPacket, !NoCalculateChecksum, !NoHWTXChecksum)
	}

	port.dumpPacket(answerPacket, dirSEND)
	answerPacket.SendPacket(port.Index)
	return dirDROP
}
