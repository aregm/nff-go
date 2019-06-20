// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lb

import (
	"crypto/sha256"
	"fmt"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

func balancer(pkt *packet.Packet, ctx flow.UserContext) bool {
	pkt.ParseL3()
	originalProtocol := pkt.Ether.EtherType
	var worker int

	// Check packet protocol number
	if originalProtocol == types.SwapARPNumber {
		err := LBConfig.InputPort.neighCache.HandleIPv4ARPPacket(pkt)
		if err != nil {
			fmt.Println(err)
		}
		return false
	} else if originalProtocol == types.SwapIPV4Number {
		ipv4 := pkt.GetIPv4NoCheck()
		if !LBConfig.TunnelSubnet.IPv4.CheckIPv4AddressWithinSubnet(ipv4.DstAddr) {
			fmt.Println("Received IPv4 packet that is not targeted at balanced subnet",
				LBConfig.TunnelPort.Subnet.IPv4.String(),
				"it is targeted at address", ipv4.DstAddr.String(), "instead. Packet dropped.")
			return false
		}
		worker = findWorkerIndexIPv4(pkt, ipv4)
	} else if originalProtocol == types.SwapIPV6Number {
		ipv6 := pkt.GetIPv6NoCheck()
		if !LBConfig.TunnelSubnet.IPv6.CheckIPv6AddressWithinSubnet(ipv6.DstAddr) {
			fmt.Println("Received IPv6 packet that is not targeted at balanced subnet",
				LBConfig.TunnelPort.Subnet.IPv6.String(),
				"it is targeted at address", ipv6.DstAddr.String(), "instead. Packet dropped.")
			return false
		}
		worker = findWorkerIndexIPv6(pkt, ipv6)
	} else {
		return false
	}

	workerIP := LBConfig.WorkerAddresses[worker]
	workerMAC, found := LBConfig.TunnelPort.neighCache.LookupMACForIPv4(workerIP)
	if !found {
		fmt.Println("Not found MAC address for IP", workerIP.String())
		LBConfig.TunnelPort.neighCache.SendARPRequestForIPv4(workerIP, LBConfig.TunnelPort.Subnet.IPv4.Addr, 0)
		return false
	}

	if !pkt.EncapsulateHead(types.EtherLen, types.IPv4MinLen+types.GRELen) {
		fmt.Println("EncapsulateHead returned error")
		return false
	}
	pkt.ParseL3()

	// Fill up L2
	pkt.Ether.SAddr = LBConfig.TunnelPort.macAddress
	pkt.Ether.DAddr = workerMAC
	pkt.Ether.EtherType = types.SwapIPV4Number

	// Fill up L3
	ipv4 := pkt.GetIPv4NoCheck()
	length := pkt.GetPacketLen()

	// construct iphdr
	ipv4.VersionIhl = 0x45
	ipv4.TypeOfService = 0
	ipv4.PacketID = 0x1513
	ipv4.FragmentOffset = 0
	ipv4.TimeToLive = 64

	ipv4.TotalLength = packet.SwapBytesUint16(uint16(length - types.EtherLen))
	ipv4.NextProtoID = types.GRENumber
	ipv4.SrcAddr = LBConfig.TunnelPort.Subnet.IPv4.Addr
	ipv4.DstAddr = workerIP
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))

	// Fill up L4
	pkt.ParseL4ForIPv4()
	gre := pkt.GetGREForIPv4()
	gre.Flags = 0
	gre.NextProto = originalProtocol

	return true
}

func findWorkerIndexIPv4(pkt *packet.Packet, ipv4 *packet.IPv4Hdr) int {
	pkt.ParseL4ForIPv4()
	hash := sha256.New()
	sa := types.IPv4ToBytes(ipv4.SrcAddr)
	hash.Write(sa[:])
	protocol := ipv4.NextProtoID
	switch protocol {
	case types.TCPNumber:
		tcp := pkt.GetTCPNoCheck()
		sp, dp := portsToByteSlices(tcp.SrcPort, tcp.DstPort)
		hash.Write(sp)
		hash.Write(dp)
	case types.UDPNumber:
		udp := pkt.GetUDPNoCheck()
		sp, dp := portsToByteSlices(udp.SrcPort, udp.DstPort)
		hash.Write(sp)
		hash.Write(dp)
	case types.ICMPNumber:
		icmp := pkt.GetICMPNoCheck()
		id, _ := portsToByteSlices(icmp.Identifier, icmp.SeqNum)
		hash.Write(id)
	}
	hash.Write([]byte{protocol})
	da := types.IPv4ToBytes(ipv4.DstAddr)
	hash.Write(da[:])

	sum := hash.Sum(nil)
	return int(sum[0]) % len(LBConfig.WorkerAddresses)
}

func findWorkerIndexIPv6(pkt *packet.Packet, ipv6 *packet.IPv6Hdr) int {
	pkt.ParseL4ForIPv6()
	hash := sha256.New()
	sa := ipv6.SrcAddr
	hash.Write(sa[:])
	protocol := ipv6.Proto
	switch protocol {
	case types.TCPNumber:
		tcp := pkt.GetTCPNoCheck()
		sp, dp := portsToByteSlices(tcp.SrcPort, tcp.DstPort)
		hash.Write(sp)
		hash.Write(dp)
	case types.UDPNumber:
		udp := pkt.GetUDPNoCheck()
		sp, dp := portsToByteSlices(udp.SrcPort, udp.DstPort)
		hash.Write(sp)
		hash.Write(dp)
	case types.ICMPv6Number:
		icmp := pkt.GetICMPNoCheck()
		id, _ := portsToByteSlices(icmp.Identifier, icmp.SeqNum)
		hash.Write(id)
	}
	hash.Write([]byte{protocol})
	da := ipv6.DstAddr
	hash.Write(da[:])

	sum := hash.Sum(nil)
	return int(sum[0]) % len(LBConfig.WorkerAddresses)
}

func portsToByteSlices(p1, p2 uint16) ([]byte, []byte) {
	a1 := make([]byte, 2)
	a1[0] = byte(p1 >> 8)
	a1[1] = byte(p1)
	a2 := make([]byte, 2)
	a2[0] = byte(p2 >> 8)
	a2[1] = byte(p2)
	return a1, a2
}
