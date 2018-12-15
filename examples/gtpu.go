// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

func main() {
	flow.SystemInit(nil)

	mainFlow := flow.SetGenerator(generate, nil)
	flow.SetHandler(mainFlow, dump, nil)
	flow.SetHandlerDrop(mainFlow, encap, nil)
	flow.SetHandler(mainFlow, dump, nil)
	flow.SetHandlerDrop(mainFlow, decap, nil)
	flow.SetHandler(mainFlow, dump, nil)
	flow.SetStopper(mainFlow)

	flow.SystemStart()
}

func decap(current *packet.Packet, context flow.UserContext) bool {
	current.ParseL3()
	ipv4 := current.GetIPv4()

	if ipv4 == nil || ipv4.DstAddr != common.BytesToIPv4(55, 66, 77, 88) {
		// reject with wrong IP
		println("ERROR")
		return false
	}

	current.ParseL4ForIPv4()
	udp := current.GetUDPForIPv4()

	if udp == nil || udp.DstPort != packet.SwapUDPPortGTPU {
		// reject un-tunneled packet
		println("ERROR")
		return false
	}

	gtpu := current.GTPIPv4FastParsing()

	if gtpu.TEID == 0 || gtpu.MessageType != packet.G_PDU {
		// reject for gtpu reasons
		println("ERROR")
		return false
	}

	if current.DecapsulateIPv4GTP() == false {
		println("ERROR")
		return false
	}
	return true
}

func encap(current *packet.Packet, context flow.UserContext) bool {
	if current.EncapsulateIPv4GTP(12345 /* TEID */) == false {
		println("ERROR")
		return false
	}

	current.ParseL3()
	ipv4 := current.GetIPv4NoCheck()
	length := current.GetPacketLen()

	// construct iphdr
	ipv4.VersionIhl = 0x45
	ipv4.TypeOfService = 0
	ipv4.PacketID = 0x1513
	ipv4.FragmentOffset = 0
	ipv4.TimeToLive = 64

	ipv4.TotalLength = packet.SwapBytesUint16(uint16(length - common.EtherLen))
	ipv4.NextProtoID = common.UDPNumber
	ipv4.SrcAddr = common.BytesToIPv4(11, 22, 33, 44)
	ipv4.DstAddr = common.BytesToIPv4(55, 66, 77, 88)
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))

	current.ParseL4ForIPv4()
	udp := current.GetUDPNoCheck()

	// construct udphdr
	udp.SrcPort = packet.SwapUDPPortGTPU
	udp.DstPort = packet.SwapUDPPortGTPU
	udp.DgramLen = uint16(length - common.EtherLen - common.IPv4MinLen)
	udp.DgramCksum = 0

	return true
}

func generate(current *packet.Packet, context flow.UserContext) {
	payload := uint(5) // GTPU message length should be 45: 20 (IPv4) + 20 (TCP) + 5 (payload)
	packet.InitEmptyIPv4TCPPacket(current, payload)
	ipv4 := current.GetIPv4NoCheck()
	tcp := current.GetTCPNoCheck()
	ipv4.SrcAddr = common.BytesToIPv4(1, 2, 3, 4)
	ipv4.DstAddr = common.BytesToIPv4(5, 6, 7, 8)
	tcp.SrcPort = packet.SwapBytesUint16(111)
	tcp.DstPort = packet.SwapBytesUint16(222)
}

var flag = 0

func dump(currentPacket *packet.Packet, context flow.UserContext) {
	if flag < 9 /*dump first three packets */ {
		fmt.Printf("%v", currentPacket.Ether)
		currentPacket.ParseL3()
		ipv4 := currentPacket.GetIPv4()
		if ipv4 != nil {
			fmt.Printf("%v", ipv4)
			tcp, udp, _ := currentPacket.ParseAllKnownL4ForIPv4()
			if tcp != nil {
				fmt.Printf("%v", tcp)
			} else if udp != nil {
				fmt.Printf("%v", udp)
				gtp := currentPacket.GTPIPv4FastParsing()
				fmt.Printf("%v", gtp)
			} else {
				println("ERROR")
			}
		} else {
			println("ERROR")
		}
		fmt.Println("----------------------------------------------------------")
		flag++
	}
}
