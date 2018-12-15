// Copyright 2017-2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"github.com/intel-go/nff-go/common"
	"net"
	"testing"
)

const N uint = 20
const payloadSizeLocal = N * 8

type Payload struct {
	array [N]uint64
}

// ground truth values (wireshark)
var (
	wantIPv4     uint16 = 0x326c
	wantIPv4TCP  uint16 = 0x8e7f
	wantIPv6TCP  uint16 = 0x7abd
	wantIPv4UDP  uint16 = 0xddd8
	wantIPv6UDP  uint16 = 0xca16
	wantIPv4ICMP uint16 = 0x61e4
	wantIPv6ICMP uint16 = 0x057b
)

/*
Pseudo header functions are covered by HW checksum test in test/stability/test_cksum
CalculatePseudoHdrIPv4TCPCksum
CalculatePseudoHdrIPv4UDPCksum
CalculatePseudoHdrIPv6TCPCksum
CalculatePseudoHdrIPv6UDPCksum
*/

func TestCalculateIPv4Checksum(t *testing.T) {
	pkt := getPacket()
	InitEmptyIPv4TCPPacket(pkt, payloadSizeLocal)
	initIPv4AddrsLocal(pkt)
	pkt.GetTCPNoCheck().Cksum = 0

	want := wantIPv4
	got := CalculateIPv4Checksum(pkt.GetIPv4())
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
		dumpPacketToPcap("TestCalculateIPv4Checksum", pkt)
	}
}

func TestCalculateIPv4TCPChecksum(t *testing.T) {
	pkt := getPacket()
	InitEmptyIPv4TCPPacket(pkt, payloadSizeLocal)
	initIPv4AddrsLocal(pkt)
	initPorts(pkt)
	initData(pkt)

	ipcksum := CalculateIPv4Checksum(pkt.GetIPv4())
	pkt.GetIPv4().HdrChecksum = SwapBytesUint16(ipcksum)

	want := wantIPv4TCP
	pkt.GetTCPNoCheck().Cksum = 0
	got := CalculateIPv4TCPChecksum(pkt.GetIPv4(), pkt.GetTCPForIPv4(), pkt.Data)
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
		dumpPacketToPcap("TestCalculateIPv4TCPChecksum", pkt)
	}
}

func TestCalculateIPv6TCPChecksum(t *testing.T) {
	pkt := getPacket()
	InitEmptyIPv6TCPPacket(pkt, payloadSizeLocal)
	initIPv6AddrsLocal(pkt)
	initPorts(pkt)
	initData(pkt)

	want := wantIPv6TCP
	pkt.GetTCPNoCheck().Cksum = 0
	got := CalculateIPv6TCPChecksum(pkt.GetIPv6(), pkt.GetTCPForIPv6(), pkt.Data)
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
		dumpPacketToPcap("TestCalculateIPv6TCPChecksum", pkt)
	}
}

func TestCalculateIPv4UDPChecksum(t *testing.T) {
	pkt := getPacket()
	InitEmptyIPv4UDPPacket(pkt, payloadSizeLocal)
	initIPv4AddrsLocal(pkt)
	initPorts(pkt)
	initData(pkt)

	ipcksum := CalculateIPv4Checksum(pkt.GetIPv4())
	pkt.GetIPv4().HdrChecksum = SwapBytesUint16(ipcksum)

	want := wantIPv4UDP
	pkt.GetUDPNoCheck().DgramCksum = 0
	got := CalculateIPv4UDPChecksum(pkt.GetIPv4(), pkt.GetUDPForIPv4(), pkt.Data)
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
		dumpPacketToPcap("TestCalculateIPv4UDPChecksum", pkt)
	}
}

func TestCalculateIPv6UDPChecksum(t *testing.T) {
	pkt := getPacket()
	InitEmptyIPv6UDPPacket(pkt, payloadSizeLocal)
	initIPv6AddrsLocal(pkt)
	initPorts(pkt)
	initData(pkt)

	want := wantIPv6UDP
	pkt.GetUDPNoCheck().DgramCksum = 0
	got := CalculateIPv6UDPChecksum(pkt.GetIPv6(), pkt.GetUDPForIPv6(), pkt.Data)
	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
		dumpPacketToPcap("TestCalculateIPv6UDPChecksum", pkt)
	}
}

func TestCalculateIPv4ICMPChecksum(t *testing.T) {
	pkt := getPacket()
	InitEmptyIPv4ICMPPacket(pkt, payloadSizeLocal)
	initIPv4AddrsLocal(pkt)
	initData(pkt)
	initICMP(pkt.GetICMPForIPv4())

	ipcksum := CalculateIPv4Checksum(pkt.GetIPv4())
	pkt.GetIPv4().HdrChecksum = SwapBytesUint16(ipcksum)

	want := wantIPv4ICMP
	got := CalculateIPv4ICMPChecksum(pkt.GetIPv4(), pkt.GetICMPForIPv4(), pkt.Data)

	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
		dumpPacketToPcap("TestCalculateIPv4ICMPChecksum", pkt)
	}
}

func TestCalculateIPv6ICMPChecksum(t *testing.T) {
	pkt := getPacket()
	InitEmptyIPv6ICMPPacket(pkt, payloadSizeLocal)
	initIPv6AddrsLocal(pkt)
	initData(pkt)
	initICMP(pkt.GetICMPForIPv6())

	want := wantIPv6ICMP
	pkt.GetICMPNoCheck().Cksum = 0
	got := CalculateIPv6ICMPChecksum(pkt.GetIPv6(), pkt.GetICMPNoCheck(), pkt.Data)

	if got != want {
		t.Errorf("Incorrect result:\ngot: %x, \nwant: %x\n\n", got, want)
		dumpPacketToPcap("TestCalculateIPv6ICMPChecksum", pkt)
	}
}

func initIPv4AddrsLocal(pkt *Packet) {
	ipv4 := pkt.GetIPv4()
	ipv4.SrcAddr = common.SliceToIPv4(net.ParseIP("131.151.32.21").To4())
	ipv4.DstAddr = common.SliceToIPv4(net.ParseIP("131.151.32.129").To4())
	ipv4.HdrChecksum = 0
}

func initIPv6AddrsLocal(pkt *Packet) {
	ipv6 := pkt.GetIPv6()
	copy(ipv6.SrcAddr[:], net.ParseIP("2001:db8:0:0:1::1")[:common.IPv6AddrLen])
	copy(ipv6.DstAddr[:], net.ParseIP("2001:db8:0:0:1::12")[:common.IPv6AddrLen])
}

func initData(pkt *Packet) {
	ptr := (*Payload)(pkt.Data)
	for i := uint(0); i < N; i++ {
		(*ptr).array[i] = uint64(i)
	}
}

func initICMP(icmp *ICMPHdr) {
	icmp.Type = 0xde
	icmp.Code = 0xad
	icmp.Identifier = SwapBytesUint16(0xbe)
	icmp.SeqNum = SwapBytesUint16(0xaf)
}
