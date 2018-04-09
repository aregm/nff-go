// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"time"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

// Tuple is a pair of address and port.
type Tuple struct {
	addr uint32
	port uint16
}

var (
	emptyEntry = Tuple{addr: 0, port: 0}
)

func (pp *portPair) allocateNewEgressConnection(protocol uint8, privEntry Tuple) (Tuple, error) {
	pp.mutex.Lock()

	port, err := pp.allocNewPort(protocol)
	if err != nil {
		pp.mutex.Unlock()
		return Tuple{}, err
	}

	publicAddr := pp.PublicPort.Subnet.Addr
	pubEntry := Tuple{
		addr: publicAddr,
		port: uint16(port),
	}

	pp.portmap[protocol][port] = portMapEntry{
		lastused:             time.Now(),
		addr:                 publicAddr,
		finCount:             0,
		terminationDirection: 0,
	}

	// Add lookup entries for packet translation
	pp.pri2pubTable[protocol].Store(privEntry, pubEntry)
	pp.pub2priTable[protocol].Store(pubEntry, privEntry)

	pp.mutex.Unlock()
	return pubEntry, nil
}

// PublicToPrivateTranslation does ingress translation.
func PublicToPrivateTranslation(pkt *packet.Packet, ctx flow.UserContext) uint {
	pi := ctx.(pairIndex)
	pp := &Natconfig.PortPairs[pi.index]

	dumpPacket(pkt, pi.index, iPUBLIC)

	// Parse packet type and address
	pktVLAN := pkt.ParseL3CheckVLAN()
	pktIPv4 := pkt.GetIPv4CheckVLAN()
	if pktIPv4 == nil {
		arp := pkt.GetARPCheckVLAN()
		if arp != nil {
			port := pp.PublicPort.handleARP(pkt)
			if port != flowDrop {
				dumpPacket(pkt, pi.index, iPUBLIC)
			} else {
				dumpDrop(pkt, pi.index, iPUBLIC)
			}
			return port
		}
		// We don't currently support anything except for IPv4 and ARP
		dumpDrop(pkt, pi.index, iPUBLIC)
		return flowDrop
	}

	pktTCP, pktUDP, pktICMP := pkt.ParseAllKnownL4ForIPv4()
	// Create a lookup key
	protocol := pktIPv4.NextProtoID
	pub2priKey := Tuple{
		addr: packet.SwapBytesUint32(pktIPv4.DstAddr),
	}
	// Parse packet destination port
	if pktTCP != nil {
		pub2priKey.port = packet.SwapBytesUint16(pktTCP.DstPort)
	} else if pktUDP != nil {
		pub2priKey.port = packet.SwapBytesUint16(pktUDP.DstPort)
	} else if pktICMP != nil {
		// Check if this ICMP packet destination is NAT itself. If
		// yes, reply back with ICMP and stop packet processing.
		port := pp.PublicPort.handleICMP(pkt)
		if port != flowOut {
			if port == flowBack {
				dumpPacket(pkt, pi.index, iPUBLIC)
			} else if port == flowDrop {
				dumpDrop(pkt, pi.index, iPUBLIC)
			}
			return port
		}
		pub2priKey.port = packet.SwapBytesUint16(pktICMP.Identifier)
	} else {
		dumpDrop(pkt, pi.index, iPUBLIC)
		return flowDrop
	}

	// Do lookup
	v, found := pp.pub2priTable[protocol].Load(pub2priKey)
	// For ingress connections packets are allowed only if a
	// connection has been previosly established with a egress
	// (private to public) packet. So if lookup fails, this incoming
	// packet is ignored.
	if !found {
		dumpDrop(pkt, pi.index, iPUBLIC)
		return flowDrop
	}
	value := v.(Tuple)

	// Check whether connection is too old
	if time.Since(pp.portmap[protocol][pub2priKey.port].lastused) <= connectionTimeout {
		pp.portmap[protocol][pub2priKey.port].lastused = time.Now()
	} else {
		// There was no transfer on this port for too long
		// time. We don't allow it any more
		pp.mutex.Lock()
		pp.deleteOldConnection(protocol, int(pub2priKey.port))
		pp.mutex.Unlock()
		dumpDrop(pkt, pi.index, iPUBLIC)
		return flowDrop
	}

	// Check whether TCP connection could be reused
	if protocol == common.TCPNumber {
		pp.checkTCPTermination(pktTCP, int(pub2priKey.port), pub2pri)
	}

	// Do packet translation
	pkt.Ether.DAddr = pp.PrivatePort.getMACForIP(value.addr)
	pkt.Ether.SAddr = pp.PrivatePort.SrcMACAddress
	if pktVLAN != nil {
		pktVLAN.SetVLANTagIdentifier(pp.PrivatePort.Vlan)
	}
	pktIPv4.DstAddr = packet.SwapBytesUint32(value.addr)

	if pktTCP != nil {
		pktTCP.DstPort = packet.SwapBytesUint16(value.port)
		setIPv4TCPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
	} else if pktUDP != nil {
		pktUDP.DstPort = packet.SwapBytesUint16(value.port)
		setIPv4UDPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
	} else {
		pktICMP.Identifier = packet.SwapBytesUint16(value.port)
		setIPv4ICMPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
	}

	dumpPacket(pkt, pi.index, iPRIVATE)
	return flowOut
}

// PrivateToPublicTranslation does egress translation.
func PrivateToPublicTranslation(pkt *packet.Packet, ctx flow.UserContext) uint {
	pi := ctx.(pairIndex)
	pp := &Natconfig.PortPairs[pi.index]

	dumpPacket(pkt, pi.index, iPRIVATE)

	// Parse packet type and address
	pktVLAN := pkt.ParseL3CheckVLAN()
	pktIPv4 := pkt.GetIPv4CheckVLAN()
	if pktIPv4 == nil {
		arp := pkt.GetARPCheckVLAN()
		if arp != nil {
			port := pp.PrivatePort.handleARP(pkt)
			if port != flowDrop {
				dumpPacket(pkt, pi.index, iPRIVATE)
			} else {
				dumpDrop(pkt, pi.index, iPRIVATE)
			}
			return port
		}
		// We don't currently support anything except for IPv4 and ARP
		dumpDrop(pkt, pi.index, iPRIVATE)
		return flowDrop
	}

	pktTCP, pktUDP, pktICMP := pkt.ParseAllKnownL4ForIPv4()

	// Create a lookup key
	protocol := pktIPv4.NextProtoID
	pri2pubKey := Tuple{
		addr: packet.SwapBytesUint32(pktIPv4.SrcAddr),
	}

	// Parse packet source port
	if pktTCP != nil {
		pri2pubKey.port = packet.SwapBytesUint16(pktTCP.SrcPort)
	} else if pktUDP != nil {
		pri2pubKey.port = packet.SwapBytesUint16(pktUDP.SrcPort)
	} else if pktICMP != nil {
		// Check if this ICMP packet destination is NAT itself. If
		// yes, reply back with ICMP and stop packet processing.
		port := pp.PrivatePort.handleICMP(pkt)
		if port != flowOut {
			if port == flowBack {
				dumpPacket(pkt, pi.index, iPRIVATE)
			} else if port == flowDrop {
				dumpDrop(pkt, pi.index, iPRIVATE)
			}
			return port
		}
		pri2pubKey.port = packet.SwapBytesUint16(pktICMP.Identifier)
	} else {
		dumpDrop(pkt, pi.index, iPRIVATE)
		return flowDrop
	}

	// Do lookup
	var value Tuple
	v, found := pp.pri2pubTable[protocol].Load(pri2pubKey)
	if !found {
		var err error
		// Store new local network entry in ARP cache
		pp.PrivatePort.ArpTable.Store(pri2pubKey.addr, pkt.Ether.SAddr)
		// Allocate new connection from private to public network
		value, err = pp.allocateNewEgressConnection(protocol, pri2pubKey)

		if err != nil {
			println("Warning! Failed to allocate new connection", err)
			dumpDrop(pkt, pi.index, iPRIVATE)
			return flowDrop
		}
	} else {
		value = v.(Tuple)
		pp.portmap[protocol][value.port].lastused = time.Now()
	}

	// Check whether TCP connection could be reused
	if pktTCP != nil {
		pp.checkTCPTermination(pktTCP, int(value.port), pri2pub)
	}

	// Do packet translation
	pkt.Ether.DAddr = pp.PublicPort.DstMACAddress
	pkt.Ether.SAddr = pp.PublicPort.SrcMACAddress
	if pktVLAN != nil {
		pktVLAN.SetVLANTagIdentifier(pp.PublicPort.Vlan)
	}
	pktIPv4.SrcAddr = packet.SwapBytesUint32(value.addr)

	if pktTCP != nil {
		pktTCP.SrcPort = packet.SwapBytesUint16(value.port)
		setIPv4TCPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
	} else if pktUDP != nil {
		pktUDP.SrcPort = packet.SwapBytesUint16(value.port)
		setIPv4UDPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
	} else {
		pktICMP.Identifier = packet.SwapBytesUint16(value.port)
		setIPv4ICMPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
	}

	dumpPacket(pkt, pi.index, iPUBLIC)
	return flowOut
}

// Simple check for FIN or RST in TCP
func (pp *portPair) checkTCPTermination(hdr *packet.TCPHdr, port int, dir terminationDirection) {
	if hdr.TCPFlags&common.TCPFlagFin != 0 {
		// First check for FIN
		pp.mutex.Lock()

		pme := &pp.portmap[common.TCPNumber][port]
		if pme.finCount == 0 {
			pme.finCount = 1
			pme.terminationDirection = dir
		} else if pme.finCount == 1 && pme.terminationDirection == ^dir {
			pme.finCount = 2
		}

		pp.mutex.Unlock()
	} else if hdr.TCPFlags&common.TCPFlagRst != 0 {
		// RST means that connection is terminated immediately
		pp.mutex.Lock()
		pp.deleteOldConnection(common.TCPNumber, port)
		pp.mutex.Unlock()
	} else if hdr.TCPFlags&common.TCPFlagAck != 0 {
		// Check for ACK last so that if there is also FIN,
		// termination doesn't happen. Last ACK should come without
		// FIN
		pp.mutex.Lock()

		pme := &pp.portmap[common.TCPNumber][port]
		if pme.finCount == 2 {
			pp.deleteOldConnection(common.TCPNumber, port)
			// Set some time while port cannot be used before
			// connection timeout is reached
			pme.lastused = time.Now().Add(time.Duration(portReuseTimeout - connectionTimeout))
		}

		pp.mutex.Unlock()
	}
}

func (port *ipv4Port) handleARP(pkt *packet.Packet) uint {
	arp := pkt.GetARPNoCheck()

	if packet.SwapBytesUint16(arp.Operation) != packet.ARPRequest {
		// We don't care about replies so far
		return flowDrop
	}

	// Check that someone is asking about MAC of my IP address and HW
	// address is blank in request
	if packet.BytesToIPv4(arp.TPA[0], arp.TPA[1], arp.TPA[2], arp.TPA[3]) != packet.SwapBytesUint32(port.Subnet.Addr) {
		println("Warning! Got an ARP packet with target IPv4 address", StringIPv4Array(arp.TPA),
			"different from IPv4 address on interface. Should be", StringIPv4Int(port.Subnet.Addr),
			". ARP request ignored.")
		return flowDrop
	}
	if arp.THA != [common.EtherAddrLen]byte{} {
		println("Warning! Got an ARP packet with non-zero MAC address", StringMAC(arp.THA),
			". ARP request ignored.")
		return flowDrop
	}

	// Prepare an answer to this request
	pkt.Ether.DAddr = pkt.Ether.SAddr
	pkt.Ether.SAddr = port.SrcMACAddress
	arp.Operation = packet.SwapBytesUint16(packet.ARPReply)
	myIP := arp.TPA
	arp.TPA = arp.SPA
	arp.THA = arp.SHA
	arp.SPA = myIP
	arp.SHA = port.SrcMACAddress

	return flowBack
}

func (port *ipv4Port) getMACForIP(ip uint32) macAddress {
	v, found := port.ArpTable.Load(ip)
	if found {
		return macAddress(v.([common.EtherAddrLen]byte))
	}
	println("Warning! IP address",
		byte(ip), ".", byte(ip>>8), ".", byte(ip>>16), ".", byte(ip>>24),
		"not found in ARP cache on port", port.Index)
	return macAddress{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

func (port *ipv4Port) handleICMP(pkt *packet.Packet) uint {
	ipv4 := pkt.GetIPv4NoCheck()

	// Check that received ICMP packet is addressed at this host
	if packet.SwapBytesUint32(ipv4.DstAddr) != port.Subnet.Addr {
		return flowOut
	}

	icmp := pkt.GetICMPNoCheck()

	// Check that received ICMP packet is echo request packet. We
	// don't support any other messages yet, so process them in normal
	// NAT way. Maybe these are packets which should be passed through
	// translation.
	if icmp.Type != common.ICMPTypeEchoRequest || icmp.Code != 0 {
		return flowOut
	}

	// Return a packet back to sender
	swapAddrIPv4(pkt)
	icmp.Type = common.ICMPTypeEchoResponse
	setIPv4ICMPChecksum(pkt, !NoCalculateChecksum, !NoHWTXChecksum)
	return flowBack
}
