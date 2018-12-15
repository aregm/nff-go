// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package flow is the main package of NFF-GO library and should be always imported by
// user application.
package flow

import (
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
)

func handleARPICMPRequests(current *packet.Packet, context UserContext) bool {
	current.ParseL3()
	arp := current.GetARPCheckVLAN()
	// ARP can be only in IPv4. IPv6 replace it with modified ICMP
	if arp != nil {
		if packet.SwapBytesUint16(arp.Operation) != packet.ARPRequest ||
			arp.THA != [common.EtherAddrLen]byte{} {
			return false
		}

		port := portPair[common.ArrayToIPv4(arp.TPA)]
		if port == nil {
			return false
		}

		// Prepare an answer to this request
		answerPacket, err := packet.NewPacket()
		if err != nil {
			common.LogFatal(common.Debug, err)
		}
		packet.InitARPReplyPacket(answerPacket, port.MAC, arp.SHA, common.ArrayToIPv4(arp.TPA), common.ArrayToIPv4(arp.SPA))
		answerPacket.SendPacket(port.port)

		return false
	}
	ipv4 := current.GetIPv4()
	if ipv4 != nil {
		current.ParseL4ForIPv4()
		icmp := current.GetICMPForIPv4()
		if icmp != nil {
			// Check that received ICMP packet is echo request packet.
			if icmp.Type != common.ICMPTypeEchoRequest || icmp.Code != 0 {
				return true
			}

			// Check that received ICMP packet is addressed at this host.
			port := portPair[ipv4.DstAddr]
			if port == nil {
				return true
			}

			// Return a packet back to sender
			answerPacket, err := packet.NewPacket()
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			// TODO need to initilize new packet instead of copying
			packet.GeneratePacketFromByte(answerPacket, current.GetRawPacketBytes())
			answerPacket.Ether.DAddr = current.Ether.SAddr
			answerPacket.Ether.SAddr = current.Ether.DAddr
			answerPacket.ParseL3()
			(answerPacket.GetIPv4NoCheck()).DstAddr = ipv4.SrcAddr
			(answerPacket.GetIPv4NoCheck()).SrcAddr = ipv4.DstAddr
			answerPacket.ParseL4ForIPv4()
			(answerPacket.GetICMPNoCheck()).Type = common.ICMPTypeEchoResponse
			ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
			answerPacket.ParseL7(common.ICMPNumber)
			icmp.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(ipv4, icmp, answerPacket.Data))

			answerPacket.SendPacket(port.port)

			return false
		}
	}
	return true
}
