// Copyright 2017-2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/vishvananda/netlink"

	upd "github.com/intel-go/nff-go/examples/nat/updatecfg"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
)

func (t *Tuple) String() string {
	return fmt.Sprintf("addr = %d.%d.%d.%d:%d",
		(t.addr>>24)&0xff,
		(t.addr>>16)&0xff,
		(t.addr>>8)&0xff,
		t.addr&0xff,
		t.port)
}

func StringIPv4Int(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(addr>>24)&0xff,
		(addr>>16)&0xff,
		(addr>>8)&0xff,
		addr&0xff)
}

func StringIPv4Array(addr [common.IPv4AddrLen]uint8) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
}

func StringMAC(mac [common.EtherAddrLen]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func swapAddrIPv4(pkt *packet.Packet) {
	ipv4 := pkt.GetIPv4NoCheck()

	pkt.Ether.SAddr, pkt.Ether.DAddr = pkt.Ether.DAddr, pkt.Ether.SAddr
	ipv4.SrcAddr, ipv4.DstAddr = ipv4.DstAddr, ipv4.SrcAddr
}

func swapAddrIPv6(pkt *packet.Packet) {
	ipv6 := pkt.GetIPv6NoCheck()

	pkt.Ether.SAddr, pkt.Ether.DAddr = pkt.Ether.DAddr, pkt.Ether.SAddr
	ipv6.SrcAddr, ipv6.DstAddr = ipv6.DstAddr, ipv6.SrcAddr
}

func (port *ipPort) startTrace(dir uint) *os.File {
	dumpNameLookup := [dirKNI + 1]string{
		"drop",
		"dump",
		"kni",
	}

	fname := fmt.Sprintf("%s-%d-%s.pcap", dumpNameLookup[dir], port.Index, packet.MACToString(port.SrcMACAddress))

	file, err := os.Create(fname)
	if err != nil {
		log.Fatal(err)
	}
	packet.WritePcapGlobalHdr(file)
	return file
}

func (port *ipPort) dumpPacket(pkt *packet.Packet, dir uint) {
	if DumpEnabled[dir] {
		port.dumpsync[dir].Lock()
		if port.fdump[dir] == nil {
			port.fdump[dir] = port.startTrace(dir)
		}

		err := pkt.WritePcapOnePacket(port.fdump[dir])
		if err != nil {
			log.Fatal(err)
		}
		port.dumpsync[dir].Unlock()
	}
}

func (port *ipPort) closePortTraces() {
	for _, f := range port.fdump {
		if f != nil {
			f.Close()
		}
	}
}

// CloseAllDumpFiles closes all debug dump files.
func CloseAllDumpFiles() {
	for i := range Natconfig.PortPairs {
		Natconfig.PortPairs[i].PrivatePort.closePortTraces()
		Natconfig.PortPairs[i].PublicPort.closePortTraces()
	}
}

func convertSubnet(s *upd.Subnet) (*ipv4Subnet, *ipv6Subnet, error) {
	a := s.GetAddress().GetAddress()
	addr, err := convertIPv4(a)
	if err != nil {
		if net.IP(a).To16() == nil {
			return nil, nil, err
		}
		ret := ipv6Subnet{}
		copy(ret.Addr[:], a)
		copy(ret.Mask[:], net.CIDRMask(int(s.GetMaskBitsNumber()), 128))
		return nil, &ret, nil
	}

	return &ipv4Subnet{
		Addr: addr,
		Mask: uint32(0xffffffff) << (32 - s.GetMaskBitsNumber()),
	}, nil, nil
}

func convertForwardedPort(p *upd.ForwardedPort) (*forwardedPort, error) {
	bytes := p.GetTargetAddress().GetAddress()
	addr, err := convertIPv4(bytes)
	var addr6 [common.IPv6AddrLen]uint8
	var ipv6 bool
	if err != nil {
		if len(bytes) == common.IPv6AddrLen {
			copy(addr6[:], bytes)
			ipv6 = true
		} else {
			return nil, err
		}
	}
	if uint8(p.GetProtocol()) != common.TCPNumber &&
		uint8(p.GetProtocol()) != common.UDPNumber &&
		p.GetProtocol() != (common.TCPNumber|upd.Protocol_IPv6_Flag) &&
		p.GetProtocol() != (common.UDPNumber|upd.Protocol_IPv6_Flag) {
		return nil, fmt.Errorf("Bad protocol identifier %d", p.GetProtocol())
	}

	return &forwardedPort{
		Port: uint16(p.GetSourcePortNumber()),
		Destination: hostPort{
			Addr4: addr,
			Addr6: addr6,
			Port:  uint16(p.GetTargetPortNumber()),
			ipv6:  ipv6,
		},
		Protocol: protocolId{
			id:   uint8(p.GetProtocol() &^ upd.Protocol_IPv6_Flag),
			ipv6: p.GetProtocol()&upd.Protocol_IPv6_Flag != 0,
		},
	}, nil
}

func setPacketDstPort(pkt *packet.Packet, ipv6 bool, port uint16, pktTCP *packet.TCPHdr, pktUDP *packet.UDPHdr, pktICMP *packet.ICMPHdr) {
	if pktTCP != nil {
		pktTCP.DstPort = packet.SwapBytesUint16(port)
		if ipv6 {
			setIPv6TCPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		} else {
			setIPv4TCPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		}
	} else if pktUDP != nil {
		pktUDP.DstPort = packet.SwapBytesUint16(port)
		if ipv6 {
			setIPv6UDPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		} else {
			setIPv4UDPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		}
	} else {
		pktICMP.Identifier = packet.SwapBytesUint16(port)
		if ipv6 {
			setIPv6ICMPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		} else {
			setIPv4ICMPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		}
	}
}

func setPacketSrcPort(pkt *packet.Packet, ipv6 bool, port uint16, pktTCP *packet.TCPHdr, pktUDP *packet.UDPHdr, pktICMP *packet.ICMPHdr) {
	if pktTCP != nil {
		pktTCP.SrcPort = packet.SwapBytesUint16(port)
		if ipv6 {
			setIPv6TCPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		} else {
			setIPv4TCPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		}
	} else if pktUDP != nil {
		pktUDP.SrcPort = packet.SwapBytesUint16(port)
		if ipv6 {
			setIPv6UDPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		} else {
			setIPv4UDPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		}
	} else {
		pktICMP.Identifier = packet.SwapBytesUint16(port)
		if ipv6 {
			setIPv6ICMPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		} else {
			setIPv4ICMPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
		}
	}
}

func ParseAllKnownL4(pkt *packet.Packet, pktIPv4 *packet.IPv4Hdr, pktIPv6 *packet.IPv6Hdr) (uint8, *packet.TCPHdr, *packet.UDPHdr, *packet.ICMPHdr, uint16, uint16) {
	var protocol uint8

	if pktIPv4 != nil {
		protocol = pktIPv4.NextProtoID
		pkt.ParseL4ForIPv4()
	} else {
		protocol = pktIPv6.Proto
		pkt.ParseL4ForIPv6()
	}

	switch protocol {
	case common.TCPNumber:
		pktTCP := (*packet.TCPHdr)(pkt.L4)
		return protocol, pktTCP, nil, nil, packet.SwapBytesUint16(pktTCP.SrcPort), packet.SwapBytesUint16(pktTCP.DstPort)
	case common.UDPNumber:
		pktUDP := (*packet.UDPHdr)(pkt.L4)
		return protocol, nil, pktUDP, nil, packet.SwapBytesUint16(pktUDP.SrcPort), packet.SwapBytesUint16(pktUDP.DstPort)
	case common.ICMPNumber:
		pktICMP := (*packet.ICMPHdr)(pkt.L4)
		return protocol, nil, nil, pktICMP, packet.SwapBytesUint16(pktICMP.Identifier), packet.SwapBytesUint16(pktICMP.Identifier)
	case common.ICMPv6Number:
		pktICMP := (*packet.ICMPHdr)(pkt.L4)
		return protocol, nil, nil, pktICMP, packet.SwapBytesUint16(pktICMP.Identifier), packet.SwapBytesUint16(pktICMP.Identifier)
	default:
		return 0, nil, nil, nil, 0, 0
	}
}

func (port *ipPort) setLinkLocalIPv4KNIAddress(ipv4addr, mask uint32) {
	if port.KNIName != "" {
		myKNI, err := netlink.LinkByName(port.KNIName)
		if err != nil {
			fmt.Println("Failed to get KNI interface", port.KNIName, ":", err)
			return
		}
		a := packet.IPv4ToBytes(ipv4addr)
		m := packet.IPv4ToBytes(mask)
		addr := &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   net.IPv4(a[3], a[2], a[1], a[0]),
				Mask: net.IPv4Mask(m[3], m[2], m[1], m[0]),
			},
		}
		fmt.Println("Setting address", addr)
		err = netlink.AddrAdd(myKNI, addr)
		if err != nil {
			fmt.Println("Failed to set interface", port.KNIName, "address", addr, ":")
		} else {
			fmt.Println("Set address", addr, "on KNI interface", port.KNIName)
		}
	}
}

func (port *ipPort) setLinkLocalIPv6KNIAddress(ipv6addr, mask [common.IPv6AddrLen]uint8) {
	if port.KNIName != "" {
		myKNI, err := netlink.LinkByName(port.KNIName)
		if err != nil {
			fmt.Println("Failed to get KNI interface", port.KNIName, ":", err)
			return
		}
		addr := &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   ipv6addr[:],
				Mask: mask[:],
			},
		}
		err = netlink.AddrAdd(myKNI, addr)
		if err != nil {
			fmt.Println("Failed to set interface", port.KNIName, "address", addr, ":", err)
		} else {
			fmt.Println("Set address", addr, "on KNI interface", port.KNIName)
		}
	}
}
