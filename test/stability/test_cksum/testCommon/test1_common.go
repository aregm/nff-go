// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testCommon

import (
	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/packet"
)

// Packetdata is a structure for packet pointer cast.
type Packetdata struct {
	F1, F2 uint64
}

// CheckPacketChecksums calculates and checks checksum for packet.
func CheckPacketChecksums(p *packet.Packet) bool {
	status := false

	if packet.SwapBytesUint16(p.Ether.EtherType) == common.IPV4Number {
		pIPv4 := p.GetIPv4()
		l3status := true
		if packet.SwapBytesUint16(pIPv4.HdrChecksum) != packet.CalculateIPv4Checksum(pIPv4) {
			println("IPv4 checksum mismatch")
			l3status = false
		}

		if pIPv4.NextProtoID == common.UDPNumber {
			pUDP := p.GetUDPForIPv4()
			csum := packet.CalculateIPv4UDPChecksum(pIPv4, pUDP, p.Data)
			if packet.SwapBytesUint16(pUDP.DgramCksum) != csum {
				println("IPv4 UDP datagram checksum mismatch", packet.SwapBytesUint16(pUDP.DgramCksum), "should be", csum)
			} else {
				status = l3status
			}
		} else if pIPv4.NextProtoID == common.TCPNumber {
			pTCP := p.GetTCPForIPv4()
			csum := packet.CalculateIPv4TCPChecksum(pIPv4, pTCP, p.Data)
			if packet.SwapBytesUint16(pTCP.Cksum) != csum {
				println("IPv4 TCP checksum mismatch", packet.SwapBytesUint16(pTCP.Cksum), "should be", csum)
			} else {
				status = l3status
			}
		} else {
			println("Unknown IPv4 protocol number", pIPv4.NextProtoID)
		}
	} else if packet.SwapBytesUint16(p.Ether.EtherType) == common.IPV6Number {
		pIPv6 := p.GetIPv6()
		if pIPv6.Proto == common.UDPNumber {
			pUDP := p.GetUDPForIPv6()
			csum := packet.CalculateIPv6UDPChecksum(pIPv6, pUDP, p.Data)
			if packet.SwapBytesUint16(pUDP.DgramCksum) != csum {
				println("IPv6 UDP datagram checksum mismatch:", packet.SwapBytesUint16(pUDP.DgramCksum), "should be", csum)
			} else {
				status = true
			}
		} else if pIPv6.Proto == common.TCPNumber {
			pTCP := p.GetTCPForIPv6()
			csum := packet.CalculateIPv6TCPChecksum(pIPv6, pTCP, p.Data)
			if packet.SwapBytesUint16(pTCP.Cksum) != csum {
				println("IPv6 TCP datagram checksum mismatch", packet.SwapBytesUint16(pTCP.Cksum), "should be", csum)
			} else {
				status = true
			}
		} else {
			println("Unknown IPv6 protocol number", pIPv6.Proto)
		}
	} else {
		println("Unknown packet EtherType", p.Ether.EtherType)
	}

	return status
}

// CalculateChecksum calculates checksum and writes to fields of packet.
func CalculateChecksum(p *packet.Packet) {
	if p.Ether.EtherType == packet.SwapBytesUint16(common.IPV4Number) {
		pIPv4 := p.GetIPv4()
		pIPv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pIPv4))

		if pIPv4.NextProtoID == common.UDPNumber {
			pUDP := p.GetUDPForIPv4()
			pUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pIPv4, pUDP, p.Data))
		} else if pIPv4.NextProtoID == common.TCPNumber {
			pTCP := p.GetTCPForIPv4()
			pTCP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(pIPv4, pTCP, p.Data))
		} else {
			println("Unknown IPv4 protocol number", pIPv4.NextProtoID)
			println("TEST FAILED")
		}
	} else if packet.SwapBytesUint16(p.Ether.EtherType) == common.IPV6Number {
		pIPv6 := p.GetIPv6()
		if pIPv6.Proto == common.UDPNumber {
			pUDP := p.GetUDPForIPv6()
			pUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv6UDPChecksum(pIPv6, pUDP, p.Data))
		} else if pIPv6.Proto == common.TCPNumber {
			pTCP := p.GetTCPForIPv6()
			pTCP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6TCPChecksum(pIPv6, pTCP, p.Data))
		} else {
			println("Unknown IPv6 protocol number", pIPv6.Proto)
			println("TEST FAILED")
		}
	} else {
		println("Unknown packet EtherType", p.Ether.EtherType)
		println("TEST FAILED")
	}
}
