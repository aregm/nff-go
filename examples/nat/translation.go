// Copyright 2017-2018 Intel Corporation.
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

type Tuple6 struct {
	addr [common.IPv6AddrLen]uint8
	port uint16
}

func (pp *portPair) allocateNewEgressConnection(ipv6 bool, protocol uint8, privEntry interface{}) (uint32, [common.IPv6AddrLen]uint8, uint16, error) {
	pp.mutex.Lock()

	port, err := pp.allocNewPort(ipv6, protocol)
	if err != nil {
		pp.mutex.Unlock()
		return 0, [common.IPv6AddrLen]uint8{}, 0, err
	}

	var pubEntry interface{}
	var v4addr uint32
	var v6addr [common.IPv6AddrLen]uint8
	if ipv6 {
		v6addr = pp.PublicPort.Subnet6.Addr
		pubEntry = Tuple6{
			addr: v6addr,
			port: uint16(port),
		}
	} else {
		v4addr = pp.PublicPort.Subnet.Addr
		pubEntry = Tuple{
			addr: v4addr,
			port: uint16(port),
		}
	}

	pp.PublicPort.getPortmap(ipv6, protocol)[port] = portMapEntry{
		lastused:             time.Now(),
		finCount:             0,
		terminationDirection: 0,
		static:               false,
	}

	// Add lookup entries for packet translation
	pp.PublicPort.translationTable[protocol].Store(pubEntry, privEntry)
	pp.PrivatePort.translationTable[protocol].Store(privEntry, pubEntry)

	pp.mutex.Unlock()
	return v4addr, v6addr, uint16(port), nil
}

// PublicToPrivateTranslation does ingress translation.
func PublicToPrivateTranslation(pkt *packet.Packet, ctx flow.UserContext) uint {
	pi := ctx.(pairIndex)
	pp := &Natconfig.PortPairs[pi.index]
	port := &pp.PublicPort

	port.dumpPacket(pkt, dirSEND)

	// Parse packet type and address
	dir, pktVLAN, pktIPv4, pktIPv6 := port.parsePacketAndCheckARP(pkt)
	if pktIPv4 == nil && pktIPv6 == nil {
		return dir
	}

	protocol, pktTCP, pktUDP, pktICMP, _, DstPort := ParseAllKnownL4(pkt, pktIPv4, pktIPv6)
	if protocol == 0 {
		// Only TCP, UDP and ICMP are supported now, all other protocols are ignored
		port.dumpPacket(pkt, dirDROP)
		return dirDROP
	}
	portNumber := DstPort
	// Create a lookup key from packet destination address and port
	pub2priKey := generateLookupKeyFromDstAddr(pkt, pktIPv4, pktIPv6, portNumber)
	// Check for ICMP traffic first
	if pktICMP != nil {
		dir := port.handleICMP(protocol, pkt, pub2priKey)
		if dir != dirSEND {
			port.dumpPacket(pkt, dir)
			return dir
		}
	}
	ipv6 := pktIPv6 != nil
	// Check for DHCP traffic. We need to get an address if it not set yet
	if pktUDP != nil {
		var handled bool
		if ipv6 {
			handled = port.handleDHCPv6(pkt)
		} else {
			handled = port.handleDHCP(pkt)
		}
		if handled {
			port.dumpPacket(pkt, dirDROP)
			return dirDROP
		}
	}

	// Do lookup
	v, found := port.translationTable[protocol].Load(pub2priKey)
	kniPresent := port.KNIName != ""

	if !found {
		// Store new local network entry in ARP cache
		var addressAcquired bool
		if ipv6 {
			port.arpTable.Store(pktIPv6.SrcAddr, pkt.Ether.SAddr)
			addressAcquired = port.Subnet6.addressAcquired
		} else {
			port.arpTable.Store(pktIPv4.SrcAddr, pkt.Ether.SAddr)
			addressAcquired = port.Subnet.addressAcquired
		}

		// For ingress connections packets are allowed only if a
		// connection has been previosly established with a egress
		// (private to public) packet. So if lookup fails, this
		// incoming packet is ignored unless there is a KNI
		// interface. If KNI is present and its IP address is known,
		// traffic is directed there.
		if kniPresent && addressAcquired {
			dir = dirKNI
		} else {
			dir = dirDROP
		}
		port.dumpPacket(pkt, dir)
		return dir
	}
	v4addr, v6addr, newPort, zeroAddr := getAddrFromTuple(v, ipv6)

	portmap := port.getPortmap(ipv6, protocol)
	// Check whether connection is too old
	if portmap[portNumber].static || time.Since(portmap[portNumber].lastused) <= connectionTimeout {
		portmap[portNumber].lastused = time.Now()
	} else {
		// There was no transfer on this port for too long
		// time. We don't allow it any more
		pp.mutex.Lock()
		pp.deleteOldConnection(pktIPv6 != nil, protocol, int(portNumber))
		pp.mutex.Unlock()
		port.dumpPacket(pkt, dirDROP)
		return dirDROP
	}

	if !zeroAddr {
		// Check whether TCP connection could be reused
		if pktTCP != nil && !portmap[portNumber].static {
			pp.checkTCPTermination(ipv6, pktTCP, int(portNumber), pub2pri)
		}

		// Find corresponding MAC address
		var mac macAddress
		var found bool
		if ipv6 {
			mac, found = port.opposite.getMACForIPv6(v6addr)
		} else {
			mac, found = port.opposite.getMACForIPv4(v4addr)
		}
		if !found {
			port.dumpPacket(pkt, dirDROP)
			return dirDROP
		}

		// Do packet translation
		pkt.Ether.DAddr = mac
		pkt.Ether.SAddr = port.SrcMACAddress
		if pktVLAN != nil {
			pktVLAN.SetVLANTagIdentifier(port.opposite.Vlan)
		}
		if ipv6 {
			pktIPv6.DstAddr = v6addr
		} else {
			pktIPv4.DstAddr = packet.SwapBytesUint32(v4addr)
		}
		setPacketDstPort(pkt, ipv6, newPort, pktTCP, pktUDP, pktICMP)

		port.dumpPacket(pkt, dirSEND)
		return dirSEND
	} else {
		port.dumpPacket(pkt, dirKNI)
		return dirKNI
	}
}

// PrivateToPublicTranslation does egress translation.
func PrivateToPublicTranslation(pkt *packet.Packet, ctx flow.UserContext) uint {
	pi := ctx.(pairIndex)
	pp := &Natconfig.PortPairs[pi.index]
	port := &pp.PrivatePort

	port.dumpPacket(pkt, dirSEND)

	// Parse packet type and address
	dir, pktVLAN, pktIPv4, pktIPv6 := port.parsePacketAndCheckARP(pkt)
	if pktIPv4 == nil && pktIPv6 == nil {
		return dir
	}

	protocol, pktTCP, pktUDP, pktICMP, SrcPort, _ := ParseAllKnownL4(pkt, pktIPv4, pktIPv6)
	if protocol == 0 {
		// Only TCP, UDP and ICMP are supported now, all other protocols are ignored
		port.dumpPacket(pkt, dirDROP)
		return dirDROP
	}
	portNumber := SrcPort
	// Create a lookup key from packet source address and port
	pri2pubKey, saddr := generateLookupKeyFromSrcAddr(pkt, pktIPv4, pktIPv6, portNumber)
	// Check for ICMP traffic first
	if pktICMP != nil {
		dir := port.handleICMP(protocol, pkt, pri2pubKey)
		if dir != dirSEND {
			port.dumpPacket(pkt, dir)
			return dir
		}
	}
	ipv6 := pktIPv6 != nil
	// Check for DHCP traffic. We need to get an address if it not set yet
	if pktUDP != nil {
		var handled bool
		if ipv6 {
			handled = port.handleDHCPv6(pkt)
		} else {
			handled = port.handleDHCP(pkt)
		}
		if handled {
			port.dumpPacket(pkt, dirDROP)
			return dirDROP
		}
	}

	kniPresent := port.KNIName != ""
	var addressAcquired bool
	var packetSentToUs bool
	if ipv6 {
		addressAcquired = port.Subnet6.addressAcquired
		packetSentToUs = port.Subnet6.Addr == pktIPv6.DstAddr ||
			port.Subnet6.llAddr == pktIPv6.DstAddr ||
			port.Subnet6.multicastAddr == pktIPv6.DstAddr ||
			port.Subnet6.llMulticastAddr == pktIPv6.DstAddr
	} else {
		addressAcquired = port.Subnet.addressAcquired
		packetSentToUs = port.Subnet.Addr == packet.SwapBytesUint32(pktIPv4.DstAddr)
	}

	// If traffic is directed at private interface IP and KNI is
	// present, this traffic is directed to KNI
	if kniPresent && addressAcquired && packetSentToUs {
		port.dumpPacket(pkt, dirKNI)
		return dirKNI
	}

	// Do lookup
	v, found := port.translationTable[protocol].Load(pri2pubKey)

	var v4addr uint32
	var v6addr [common.IPv6AddrLen]uint8
	var newPort uint16
	var zeroAddr bool

	if !found {
		var err error
		// Store new local network entry in ARP cache
		port.arpTable.Store(saddr, pkt.Ether.SAddr)

		var publicAddressAcquired bool
		if ipv6 {
			publicAddressAcquired = port.opposite.Subnet6.addressAcquired
		} else {
			publicAddressAcquired = port.opposite.Subnet.addressAcquired
		}

		if !addressAcquired || !publicAddressAcquired {
			// No packets are allowed yet because ports address is not
			// known yet
			port.dumpPacket(pkt, dirDROP)
			return dirDROP
		}
		// Allocate new connection from private to public network
		v4addr, v6addr, newPort, err = pp.allocateNewEgressConnection(pktIPv6 != nil, protocol, pri2pubKey)

		if err != nil {
			println("Warning! Failed to allocate new connection", err)
			port.dumpPacket(pkt, dirDROP)
			return dirDROP
		}
		zeroAddr = false
	} else {
		v4addr, v6addr, newPort, zeroAddr = getAddrFromTuple(v, ipv6)
		pp.PublicPort.getPortmap(ipv6, protocol)[newPort].lastused = time.Now()
	}

	if !zeroAddr {
		// Check whether TCP connection could be reused
		if pktTCP != nil && !pp.PublicPort.getPortmap(ipv6, protocol)[newPort].static {
			pp.checkTCPTermination(ipv6, pktTCP, int(newPort), pri2pub)
		}

		// Find corresponding MAC address
		var mac macAddress
		var found bool
		if pktIPv6 != nil {
			mac, found = port.opposite.getMACForIPv6(pktIPv6.DstAddr)
		} else {
			mac, found = port.opposite.getMACForIPv4(packet.SwapBytesUint32(pktIPv4.DstAddr))
		}
		if !found {
			port.dumpPacket(pkt, dirDROP)
			return dirDROP
		}

		// Do packet translation
		pkt.Ether.DAddr = mac
		pkt.Ether.SAddr = port.SrcMACAddress
		if pktVLAN != nil {
			pktVLAN.SetVLANTagIdentifier(port.opposite.Vlan)
		}
		if ipv6 {
			pktIPv6.SrcAddr = v6addr
		} else {
			pktIPv4.SrcAddr = packet.SwapBytesUint32(v4addr)
		}
		setPacketSrcPort(pkt, ipv6, newPort, pktTCP, pktUDP, pktICMP)

		port.dumpPacket(pkt, dirSEND)
		return dirSEND
	} else {
		port.dumpPacket(pkt, dirKNI)
		return dirKNI
	}
}

// Used to generate key in public to private translation
func generateLookupKeyFromDstAddr(pkt *packet.Packet, pktIPv4 *packet.IPv4Hdr, pktIPv6 *packet.IPv6Hdr, port uint16) interface{} {
	if pktIPv4 != nil {
		key := Tuple{
			addr: packet.SwapBytesUint32(pktIPv4.DstAddr),
			port: port,
		}
		return key
	} else {
		return Tuple6{
			addr: pktIPv6.DstAddr,
			port: port,
		}
	}
}

// Used to generate key in private to public translation
func generateLookupKeyFromSrcAddr(pkt *packet.Packet, pktIPv4 *packet.IPv4Hdr, pktIPv6 *packet.IPv6Hdr, port uint16) (interface{}, interface{}) {
	if pktIPv4 != nil {
		saddr := packet.SwapBytesUint32(pktIPv4.SrcAddr)
		return Tuple{
			addr: saddr,
			port: port,
		}, saddr
	} else {
		return Tuple6{
			addr: pktIPv6.SrcAddr,
			port: port,
		}, pktIPv6.SrcAddr
	}
}

// Simple check for FIN or RST in TCP
func (pp *portPair) checkTCPTermination(ipv6 bool, hdr *packet.TCPHdr, port int, dir terminationDirection) {
	if hdr.TCPFlags&common.TCPFlagFin != 0 {
		// First check for FIN
		pp.mutex.Lock()

		pme := &pp.PublicPort.portmap[common.TCPNumber][port]
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
		pp.deleteOldConnection(ipv6, common.TCPNumber, port)
		pp.mutex.Unlock()
	} else if hdr.TCPFlags&common.TCPFlagAck != 0 {
		// Check for ACK last so that if there is also FIN,
		// termination doesn't happen. Last ACK should come without
		// FIN
		pp.mutex.Lock()

		pme := &pp.PublicPort.portmap[common.TCPNumber][port]
		if pme.finCount == 2 {
			pp.deleteOldConnection(ipv6, common.TCPNumber, port)
			// Set some time while port cannot be used before
			// connection timeout is reached
			pme.lastused = time.Now().Add(time.Duration(portReuseTimeout - connectionTimeout))
		}

		pp.mutex.Unlock()
	}
}

func (port *ipPort) parsePacketAndCheckARP(pkt *packet.Packet) (dir uint, vlanhdr *packet.VLANHdr, ipv4hdr *packet.IPv4Hdr, ipv6hdr *packet.IPv6Hdr) {
	pktVLAN := pkt.ParseL3CheckVLAN()
	pktIPv4 := pkt.GetIPv4CheckVLAN()
	if pktIPv4 == nil {
		pktIPv6 := pkt.GetIPv6CheckVLAN()
		if pktIPv6 == nil {
			arp := pkt.GetARPCheckVLAN()
			if arp != nil {
				dir := port.handleARP(pkt)
				port.dumpPacket(pkt, dir)
				return dir, pktVLAN, nil, nil
			}
			port.dumpPacket(pkt, dirDROP)
			return dirDROP, pktVLAN, nil, nil
		}
		return dirSEND, pktVLAN, nil, pktIPv6
	}
	return dirSEND, pktVLAN, pktIPv4, nil
}

func getAddrFromTuple(v interface{}, ipv6 bool) (uint32, [common.IPv6AddrLen]uint8, uint16, bool) {
	if ipv6 {
		value := v.(Tuple6)
		return 0, value.addr, value.port, value.addr == [common.IPv6AddrLen]uint8{}
	} else {
		value := v.(Tuple)
		return value.addr, [common.IPv6AddrLen]uint8{}, value.port, value.addr == 0
	}
}
