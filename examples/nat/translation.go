// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"fmt"
	"sync"
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
	// Main lookup table which contains entries
	pri2pubTable []sync.Map
	pub2priTable []sync.Map
	mutex        sync.Mutex

	emptyEntry = Tuple{addr: 0, port: 0}
)

func init() {
	pri2pubTable = make([]sync.Map, common.UDPNumber+1)
	pub2priTable = make([]sync.Map, common.UDPNumber+1)
}

func allocateNewEgressConnection(protocol uint8, privEntry Tuple, publicAddr uint32) (Tuple, error) {
	mutex.Lock()

	port, err := allocNewPort(protocol)
	if err != nil {
		mutex.Unlock()
		return Tuple{}, err
	}

	pubEntry := Tuple{
		addr: publicAddr,
		port: uint16(port),
	}

	portmap[protocol][port] = portMapEntry{
		lastused:             time.Now(),
		addr:                 publicAddr,
		finCount:             0,
		terminationDirection: 0,
	}

	pri2pubTable[protocol].Store(privEntry, pubEntry)
	pub2priTable[protocol].Store(pubEntry, privEntry)

	mutex.Unlock()
	return pubEntry, nil
}

// PublicToPrivateTranslation does ingress translation.
func PublicToPrivateTranslation(pkt *packet.Packet, ctx flow.UserContext) bool {
	// Parse packet type and address
	pktIPv4, _ := pkt.ParseAllKnownL3()
	if pktIPv4 == nil {
		// We don't currently support anything except for IPv4
		return false
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
		pub2priKey.port = pktICMP.Identifier
	} else {
		return false
	}

	// Do lookup
	v, found := pub2priTable[protocol].Load(pub2priKey)
	// For ingress connections packets are allowed only if a
	// connection has been previosly established with a egress
	// (private to public) packet. So if lookup fails, this incoming
	// packet is ignored.
	if !found {
		return false
	}
	value := v.(Tuple)

	// Check whether connection is too old
	if portmap[protocol][pub2priKey.port].lastused.Add(connectionTimeout).After(time.Now()) {
		portmap[protocol][pub2priKey.port].lastused = time.Now()
	} else {
		// There was no transfer on this port for too long
		// time. We don't allow it any more
		mutex.Lock()
		deleteOldConnection(protocol, int(pub2priKey.port))
		mutex.Unlock()
		return false
	}

	// Check whether TCP connection could be reused
	if protocol == common.TCPNumber {
		checkTCPTermination(pktTCP, int(pub2priKey.port), pub2pri)
	}

	pi := ctx.(pairIndex)
	// Do packet translation
	pkt.Ether.DAddr = Natconfig.PortPairs[pi.index].PrivatePort.DstMACAddress
	pkt.Ether.SAddr = PrivateMAC[pi.index]
	pktIPv4.DstAddr = packet.SwapBytesUint32(value.addr)

	if pktTCP != nil {
		pktTCP.DstPort = packet.SwapBytesUint16(value.port)
		setIPv4TCPChecksum(pktIPv4, pktTCP, CalculateChecksum, HWTXChecksum)
	} else if pktUDP != nil {
		pktUDP.DstPort = packet.SwapBytesUint16(value.port)
		setIPv4UDPChecksum(pktIPv4, pktUDP, CalculateChecksum, HWTXChecksum)
	} else {
		setIPv4ICMPChecksum(pktIPv4, pktICMP, CalculateChecksum, HWTXChecksum)
	}

	return true
}

// PrivateToPublicTranslation does egress translation.
func PrivateToPublicTranslation(pkt *packet.Packet, ctx flow.UserContext) bool {
	// Parse packet type and address
	pktIPv4, _ := pkt.ParseAllKnownL3()
	if pktIPv4 == nil {
		// We don't currently support anything except for IPv4
		return false
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
		pri2pubKey.port = pktICMP.Identifier
	} else {
		return false
	}

	pi := ctx.(pairIndex)
	// Do lookup
	var value Tuple
	v, found := pri2pubTable[protocol].Load(pri2pubKey)
	if !found {
		var err error
		value, err = allocateNewEgressConnection(protocol, pri2pubKey,
			Natconfig.PortPairs[pi.index].PublicPort.Subnet.Addr)

		if err != nil {
			println("Warning! Failed to allocate new connection", err)
			return false
		}
	} else {
		value = v.(Tuple)
		portmap[protocol][value.port].lastused = time.Now()
	}

	// Check whether TCP connection could be reused
	if pktTCP != nil {
		checkTCPTermination(pktTCP, int(value.port), pri2pub)
	}

	// Do packet translation
	pkt.Ether.DAddr = Natconfig.PortPairs[pi.index].PublicPort.DstMACAddress
	pkt.Ether.SAddr = PublicMAC[pi.index]
	pktIPv4.SrcAddr = packet.SwapBytesUint32(value.addr)

	if pktTCP != nil {
		pktTCP.SrcPort = packet.SwapBytesUint16(value.port)
		setIPv4TCPChecksum(pktIPv4, pktTCP, CalculateChecksum, HWTXChecksum)
	} else if pktUDP != nil {
		pktUDP.SrcPort = packet.SwapBytesUint16(value.port)
		setIPv4UDPChecksum(pktIPv4, pktUDP, CalculateChecksum, HWTXChecksum)
	} else {
		setIPv4ICMPChecksum(pktIPv4, pktICMP, CalculateChecksum, HWTXChecksum)
	}

	return true
}

// Simple check for FIN or RST in TCP
func checkTCPTermination(hdr *packet.TCPHdr, port int, dir terminationDirection) {
	if hdr.TCPFlags&common.TCPFlagFin != 0 {
		// First check for FIN
		mutex.Lock()

		pme := &portmap[common.TCPNumber][port]
		if pme.finCount == 0 {
			pme.finCount = 1
			pme.terminationDirection = dir
		} else if pme.finCount == 1 && pme.terminationDirection == ^dir {
			pme.finCount = 2
		}

		mutex.Unlock()
	} else if hdr.TCPFlags&common.TCPFlagRst != 0 {
		// RST means that connection is terminated immediately
		mutex.Lock()
		deleteOldConnection(common.TCPNumber, port)
		mutex.Unlock()
	} else if hdr.TCPFlags&common.TCPFlagAck != 0 {
		// Check for ACK last so that if there is also FIN,
		// termination doesn't happen. Last ACK should come without
		// FIN
		mutex.Lock()

		pme := &portmap[common.TCPNumber][port]
		if pme.finCount == 2 {
			deleteOldConnection(common.TCPNumber, port)
		}

		mutex.Unlock()
	}
}
