// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet_test

import (
	"encoding/binary"
	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/packet"
	"net"
	"testing"
)

const N uint = 20
const payloadSize = N * 8

type Payload struct {
	array [N]uint64
}

// ground truth values (wireshark)
var (
	wantIPv4     uint16 = 0x726c
	wantIPv4TCP  uint16 = 0x8e7f
	wantIPv6TCP  uint16 = 0x7abd
	wantIPv4UDP  uint16 = 0xddd8
	wantIPv6UDP  uint16 = 0xca16
	wantIPv4ICMP uint16 = 0x41ff
	wantIPv6ICMP uint16 = 0x41ff
)

/*
Pseudo header functions are covered by HW checksum test in test/stability/test_cksum
CalculatePseudoHdrIPv4TCPCksum
CalculatePseudoHdrIPv4UDPCksum
CalculatePseudoHdrIPv6TCPCksum
CalculatePseudoHdrIPv6UDPCksum
*/

func TestCalculateIPv4Checksum(t *testing.T) {
	pkt := packet.GetPacket()
	packet.InitEmptyIPv4TCPPacket(pkt, payloadSize)
	initIPv4Addrs(pkt)

	want := wantIPv4
	got := packet.CalculateIPv4Checksum(pkt.GetIPv4())
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
	}
}

func TestCalculateIPv4TCPChecksum(t *testing.T) {
	pkt := packet.GetPacket()
	packet.InitEmptyIPv4TCPPacket(pkt, payloadSize)
	initIPv4Addrs(pkt)
	initPorts(pkt)
	initData(pkt)

	ipcksum := packet.CalculateIPv4Checksum(pkt.GetIPv4())
	pkt.GetIPv4().HdrChecksum = packet.SwapBytesUint16(ipcksum)

	want := wantIPv4TCP
	got := packet.CalculateIPv4TCPChecksum(pkt.GetIPv4(), pkt.GetTCPForIPv4(), pkt.Data)
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
	}
}

func TestCalculateIPv6TCPChecksum(t *testing.T) {
	pkt := packet.GetPacket()
	packet.InitEmptyIPv6TCPPacket(pkt, payloadSize)
	initIPv6Addrs(pkt)
	initPorts(pkt)
	initData(pkt)

	want := wantIPv6TCP
	got := packet.CalculateIPv6TCPChecksum(pkt.GetIPv6(), pkt.GetTCPForIPv6(), pkt.Data)
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
	}
}

func TestCalculateIPv4UDPChecksum(t *testing.T) {
	pkt := packet.GetPacket()
	packet.InitEmptyIPv4UDPPacket(pkt, payloadSize)
	initIPv4Addrs(pkt)
	initPorts(pkt)
	initData(pkt)

	ipcksum := packet.CalculateIPv4Checksum(pkt.GetIPv4())
	pkt.GetIPv4().HdrChecksum = packet.SwapBytesUint16(ipcksum)

	want := wantIPv4UDP
	got := packet.CalculateIPv4UDPChecksum(pkt.GetIPv4(), pkt.GetUDPForIPv4(), pkt.Data)
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
	}
}

func TestCalculateIPv6UDPChecksum(t *testing.T) {
	pkt := packet.GetPacket()
	packet.InitEmptyIPv6UDPPacket(pkt, payloadSize)
	initIPv6Addrs(pkt)
	initPorts(pkt)
	initData(pkt)

	want := wantIPv6UDP
	got := packet.CalculateIPv6UDPChecksum(pkt.GetIPv6(), pkt.GetUDPForIPv6(), pkt.Data)
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
	}
}

func TestCalculateIPv4ICMPChecksum(t *testing.T) {
	pkt := packet.GetPacket()
	packet.InitEmptyIPv4ICMPPacket(pkt, payloadSize)
	initIPv4Addrs(pkt)
	initData(pkt)

	ipcksum := packet.CalculateIPv4Checksum(pkt.GetIPv4())
	pkt.GetIPv4().HdrChecksum = packet.SwapBytesUint16(ipcksum)

	want := wantIPv4ICMP
	got := packet.CalculateIPv4ICMPChecksum(pkt.GetIPv4(), pkt.GetICMPForIPv4(), pkt.Data)
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
	}
}

func TestCalculateIPv6ICMPChecksum(t *testing.T) {
	pkt := packet.GetPacket()
	packet.InitEmptyIPv6ICMPPacket(pkt, payloadSize)
	initIPv6Addrs(pkt)
	initData(pkt)

	want := wantIPv6ICMP
	got := packet.CalculateIPv6ICMPChecksum(pkt.GetIPv6(), pkt.GetICMPForIPv6(), pkt.Data)
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
	}
}

func initEtherAddrs(pkt *packet.Packet) {
	pkt.Ether.SAddr = [common.EtherAddrLen]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	pkt.Ether.DAddr = [common.EtherAddrLen]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
}

func initIPv4Addrs(pkt *packet.Packet) {
	ipv4 := pkt.GetIPv4()
	ipv4.SrcAddr = binary.LittleEndian.Uint32(net.ParseIP("131.151.32.21").To4())
	ipv4.DstAddr = binary.LittleEndian.Uint32(net.ParseIP("131.151.32.129").To4())
}

func initIPv6Addrs(pkt *packet.Packet) {
	ipv6 := pkt.GetIPv6()
	copy(ipv6.SrcAddr[:], net.ParseIP("2001:db8:0:0:1::1")[:common.IPv6AddrLen])
	copy(ipv6.DstAddr[:], net.ParseIP("2001:db8:0:0:1::12")[:common.IPv6AddrLen])
}

func initPorts(pkt *packet.Packet) {
	// Src and Dst port numbers placed at the same offset from L4 start in both tcp and udp
	l4 := (*packet.UDPHdr)(pkt.L4)
	l4.SrcPort = packet.SwapBytesUint16(1234)
	l4.DstPort = packet.SwapBytesUint16(5678)
}

func initData(pkt *packet.Packet) {
	ptr := (*Payload)(pkt.Data)
	for i := uint(0); i < N; i++ {
		(*ptr).array[i] = uint64(i)
	}
}
