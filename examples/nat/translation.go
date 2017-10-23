// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"fmt"
	"os"
	"time"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

// Tuple is a pair of address and port.
type Tuple struct {
	addr uint32
	port uint16
}

func (t *Tuple) String() string {
	return fmt.Sprintf("addr = %d.%d.%d.%d:%d",
		(t.addr>>24)&0xff,
		(t.addr>>16)&0xff,
		(t.addr>>8)&0xff,
		t.addr&0xff,
		t.port)
}

var (
	emptyEntry = Tuple{addr: 0, port: 0}

	// Debug variables
	debugDump = false
	fdump     []*os.File
)

func swapAddrIPv4(pkt *packet.Packet) {
	ipv4 := pkt.GetIPv4()

	pkt.Ether.SAddr, pkt.Ether.DAddr = pkt.Ether.DAddr, pkt.Ether.SAddr
	ipv4.SrcAddr, ipv4.DstAddr = ipv4.DstAddr, ipv4.SrcAddr
}

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

func dumpInput(pkt *packet.Packet, index int) {
	if debugDump {
		// Dump input packet
		if fdump[index] == nil {
			fdump[index], _ = os.Create(fmt.Sprintf("%ddump.pcap", index))
			packet.WritePcapGlobalHdr(fdump[index])
			pkt.WritePcapOnePacket(fdump[index])
		}

		pkt.WritePcapOnePacket(fdump[index])
	}
}

func dumpOutput(pkt *packet.Packet, index int) {
	if debugDump {
		pkt.WritePcapOnePacket(fdump[index])
	}
}

// PublicToPrivateTranslation does ingress translation.
func PublicToPrivateTranslation(pkt *packet.Packet, ctx flow.UserContext) uint {
	pi := ctx.(pairIndex)
	pp := &Natconfig.PortPairs[pi.index]

	dumpInput(pkt, pi.index)

	// Parse packet type and address
	pkt.ParseL3()
	pktIPv4 := pkt.GetIPv4()
	if pktIPv4 == nil {
		arp := pkt.GetARP()
		if arp != nil {
			port := pp.PublicPort.handleARP(pkt)
			if port != flowDrop {
				dumpOutput(pkt, pi.index)
			}
			return port
		}
		// We don't currently support anything except for IPv4 and ARP
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
				dumpOutput(pkt, pi.index)
			}
			return port
		}
		pub2priKey.port = packet.SwapBytesUint16(pktICMP.Identifier)
	} else {
		return flowDrop
	}

	// Do lookup
	v, found := pp.pub2priTable[protocol].Load(pub2priKey)
	// For ingress connections packets are allowed only if a
	// connection has been previosly established with a egress
	// (private to public) packet. So if lookup fails, this incoming
	// packet is ignored.
	if !found {
		return flowDrop
	}
	value := v.(Tuple)

	// Check whether connection is too old
	if pp.portmap[protocol][pub2priKey.port].lastused.Add(connectionTimeout).After(time.Now()) {
		pp.portmap[protocol][pub2priKey.port].lastused = time.Now()
	} else {
		// There was no transfer on this port for too long
		// time. We don't allow it any more
		pp.mutex.Lock()
		pp.deleteOldConnection(protocol, int(pub2priKey.port))
		pp.mutex.Unlock()
		return flowDrop
	}

	// Check whether TCP connection could be reused
	if protocol == common.TCPNumber {
		pp.checkTCPTermination(pktTCP, int(pub2priKey.port), pub2pri)
	}

	// Do packet translation
	pkt.Ether.DAddr = pp.PrivatePort.getMACForIP(value.addr)
	pkt.Ether.SAddr = pp.PrivatePort.SrcMACAddress
	pktIPv4.DstAddr = packet.SwapBytesUint32(value.addr)

	if pktTCP != nil {
		pktTCP.DstPort = packet.SwapBytesUint16(value.port)
		setIPv4TCPChecksum(pkt, pktIPv4, pktTCP, CalculateChecksum, HWTXChecksum)
	} else if pktUDP != nil {
		pktUDP.DstPort = packet.SwapBytesUint16(value.port)
		setIPv4UDPChecksum(pkt, pktIPv4, pktUDP, CalculateChecksum, HWTXChecksum)
	} else {
		pktICMP.Identifier = packet.SwapBytesUint16(value.port)
		setIPv4ICMPChecksum(pkt, pktIPv4, pktICMP, CalculateChecksum, HWTXChecksum)
	}

	dumpOutput(pkt, pi.index)
	return flowOut
}

// PrivateToPublicTranslation does egress translation.
func PrivateToPublicTranslation(pkt *packet.Packet, ctx flow.UserContext) uint {
	pi := ctx.(pairIndex)
	pp := &Natconfig.PortPairs[pi.index]

	dumpInput(pkt, pi.index)

	// Parse packet type and address
	pkt.ParseL3()
	pktIPv4 := pkt.GetIPv4()
	if pktIPv4 == nil {
		arp := pkt.GetARP()
		if arp != nil {
			port := pp.PrivatePort.handleARP(pkt)
			if port != flowDrop {
				dumpOutput(pkt, pi.index)
			}
			return port
		}
		// We don't currently support anything except for IPv4 and ARP
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
				dumpOutput(pkt, pi.index)
			}
			return port
		}
		pri2pubKey.port = packet.SwapBytesUint16(pktICMP.Identifier)
	} else {
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
	pktIPv4.SrcAddr = packet.SwapBytesUint32(value.addr)

	if pktTCP != nil {
		pktTCP.SrcPort = packet.SwapBytesUint16(value.port)
		setIPv4TCPChecksum(pkt, pktIPv4, pktTCP, CalculateChecksum, HWTXChecksum)
	} else if pktUDP != nil {
		pktUDP.SrcPort = packet.SwapBytesUint16(value.port)
		setIPv4UDPChecksum(pkt, pktIPv4, pktUDP, CalculateChecksum, HWTXChecksum)
	} else {
		pktICMP.Identifier = packet.SwapBytesUint16(value.port)
		setIPv4ICMPChecksum(pkt, pktIPv4, pktICMP, CalculateChecksum, HWTXChecksum)
	}

	dumpOutput(pkt, pi.index)
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
		}

		pp.mutex.Unlock()
	}
}

func (port *ipv4Port) handleARP(pkt *packet.Packet) uint {
	arp := pkt.GetARP()

	if packet.SwapBytesUint16(arp.Operation) != packet.ARPRequest {
		// We don't care about replies so far
		return flowDrop
	}

	// Check that someone is asking about MAC of my IP address and HW
	// address is blank in request
	if packet.BytesToIPv4(arp.TPA[0], arp.TPA[1], arp.TPA[2], arp.TPA[3]) != packet.SwapBytesUint32(port.Subnet.Addr) ||
		arp.THA != [common.EtherAddrLen]byte{} {
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
	ipv4 := pkt.GetIPv4()

	// Check that received ICMP packet is addressed at this host
	if packet.SwapBytesUint32(ipv4.DstAddr) != port.Subnet.Addr {
		return flowOut
	}

	icmp := pkt.GetICMPForIPv4()

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
	icmp.Cksum = 0
	setIPv4ICMPChecksum(pkt, ipv4, icmp, CalculateChecksum, HWTXChecksum)
	return flowBack
}
