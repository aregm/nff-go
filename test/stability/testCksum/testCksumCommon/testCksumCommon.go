// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testCksumCommon

import (
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
)

// Packetdata is a structure for packet pointer cast.
type Packetdata struct {
	F1, F2 uint64
}

// CheckPacketChecksums calculates and checks checksum for packet.
func CheckPacketChecksums(p *packet.Packet) bool {
	status := false

	if p.GetEtherType() == common.IPV4Number {
		pIPv4 := p.GetIPv4CheckVLAN()
		csum := packet.CalculateIPv4Checksum(pIPv4)
		l3status := true
		if packet.SwapBytesUint16(pIPv4.HdrChecksum) != csum {
			println("IPv4 checksum mismatch", packet.SwapBytesUint16(pIPv4.HdrChecksum), "should be", csum)
			l3status = false
		}
		if pIPv4.NextProtoID == common.UDPNumber {
			pUDP := p.GetUDPForIPv4()
			csum := packet.CalculateIPv4UDPChecksum(pIPv4, pUDP, p.Data)
			if packet.SwapBytesUint16(pUDP.DgramCksum) != csum {
				if pUDP.DgramCksum == 0 {
					println("WARNING! IPv4 UDP datagram checksum value 0 means that checksum is not specified. This should not appear in this test, but ignoring for now because this is how VirtualBox works.")
					status = l3status
				} else {
					println("IPv4 UDP datagram checksum mismatch", packet.SwapBytesUint16(pUDP.DgramCksum), "should be", csum)
				}
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
		} else if pIPv4.NextProtoID == common.ICMPNumber {
			pICMP := p.GetICMPForIPv4()
			csum := packet.CalculateIPv4ICMPChecksum(pIPv4, pICMP, p.Data)
			if packet.SwapBytesUint16(pICMP.Cksum) != csum {
				println("IPv4 ICMP checksum mismatch", packet.SwapBytesUint16(pICMP.Cksum), "should be", csum)
			} else {
				status = l3status
			}
		} else {
			println("Unknown IPv4 protocol number", pIPv4.NextProtoID)
		}
	} else if p.GetEtherType() == common.IPV6Number {
		pIPv6 := p.GetIPv6CheckVLAN()
		if pIPv6.Proto == common.UDPNumber {
			pUDP := p.GetUDPForIPv6()
			csum := packet.CalculateIPv6UDPChecksum(pIPv6, pUDP, p.Data)
			if packet.SwapBytesUint16(pUDP.DgramCksum) != csum {
				if pUDP.DgramCksum == 0 {
					println("WARNING! Illegal IPv6 UDP datagram checksum value 0 specified. This should not appear in this test, but ignoring for now because this is how VirtualBox works.")
					status = true
				} else {
					println("IPv6 UDP datagram checksum mismatch:", packet.SwapBytesUint16(pUDP.DgramCksum), "should be", csum)
				}
			} else {
				status = true
			}
		} else if pIPv6.Proto == common.TCPNumber {
			pTCP := p.GetTCPForIPv6()
			csum := packet.CalculateIPv6TCPChecksum(pIPv6, pTCP, p.Data)
			if packet.SwapBytesUint16(pTCP.Cksum) != csum {
				println("IPv6 TCP checksum mismatch", packet.SwapBytesUint16(pTCP.Cksum), "should be", csum)
			} else {
				status = true
			}
		} else if pIPv6.Proto == common.ICMPNumber {
			pICMP := p.GetICMPForIPv6()
			csum := packet.CalculateIPv6ICMPChecksum(pIPv6, pICMP, p.Data)
			if packet.SwapBytesUint16(pICMP.Cksum) != csum {
				println("IPv6 ICMP checksum mismatch", packet.SwapBytesUint16(pICMP.Cksum), "should be", csum)
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
	if p.GetEtherType() == common.IPV4Number {
		pIPv4 := p.GetIPv4NoCheck()
		pIPv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pIPv4))

		if pIPv4.NextProtoID == common.UDPNumber {
			pUDP := p.GetUDPForIPv4()
			pUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pIPv4, pUDP, p.Data))
		} else if pIPv4.NextProtoID == common.TCPNumber {
			pTCP := p.GetTCPForIPv4()
			pTCP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(pIPv4, pTCP, p.Data))
		} else if pIPv4.NextProtoID == common.ICMPNumber {
			pICMP := p.GetICMPForIPv4()
			pICMP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(pIPv4, pICMP, p.Data))
		} else {
			println("Unknown IPv4 protocol number", pIPv4.NextProtoID)
			println("TEST FAILED")
		}
	} else if p.GetEtherType() == common.IPV6Number {
		pIPv6 := p.GetIPv6NoCheck()
		if pIPv6.Proto == common.UDPNumber {
			pUDP := p.GetUDPForIPv6()
			pUDP.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv6UDPChecksum(pIPv6, pUDP, p.Data))
		} else if pIPv6.Proto == common.TCPNumber {
			pTCP := p.GetTCPForIPv6()
			pTCP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6TCPChecksum(pIPv6, pTCP, p.Data))
		} else if pIPv6.Proto == common.ICMPNumber {
			pICMP := p.GetICMPForIPv6()
			pICMP.Cksum = packet.SwapBytesUint16(packet.CalculateIPv6ICMPChecksum(pIPv6, pICMP, p.Data))
		} else {
			println("Unknown IPv6 protocol number", pIPv6.Proto)
			println("TEST FAILED")
		}
	} else {
		println("Unknown packet EtherType", p.Ether.EtherType)
		println("TEST FAILED")
	}
}
