// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"reflect"
	"testing"
	"unsafe"

	"github.com/intel-go/yanff/low"
	. "github.com/intel-go/yanff/packet"
)

func init() {
	argc, argv := low.ParseFlags()
	// burstSize=32, mbufNumber=8191, mbufCacheSize=250
	low.InitDPDK(argc, argv, 32, 8191, 250)
}

var MacHeader = [8]EtherHdr{
	{
		DAddr:     [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SAddr:     [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51},
		EtherType: SwapBytesUint16(IPV4Number),
	},
	{
		DAddr:     [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SAddr:     [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51},
		EtherType: SwapBytesUint16(IPV4Number),
	},
	{
		DAddr:     [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SAddr:     [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x52},
		EtherType: SwapBytesUint16(IPV4Number),
	},
	{
		DAddr:     [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SAddr:     [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x52},
		EtherType: SwapBytesUint16(IPV4Number),
	},
	{
		DAddr:     [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SAddr:     [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x52},
		EtherType: SwapBytesUint16(IPV4Number),
	},
	{
		DAddr:     [6]uint8{0x00, 0x12, 0x22, 0x33, 0x44, 0x55},
		SAddr:     [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x52},
		EtherType: SwapBytesUint16(IPV4Number),
	},
	{
		DAddr:     [6]uint8{0x10, 0x11, 0x22, 0x33, 0x44, 0x55},
		SAddr:     [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51},
		EtherType: SwapBytesUint16(IPV4Number),
	},
	{
		DAddr:     [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SAddr:     [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51},
		EtherType: SwapBytesUint16(IPV4Number),
	},
}

// TODO: Current tests does not test IPv6 headers parsing. Need to add IPv6 headers into test set
var IPHeader = [7]IPv4Hdr{
	{
		VersionIhl:     0x45,
		TypeOfService:  0x00,
		TotalLength:    0x2e00,
		PacketID:       0xfdbf,
		FragmentOffset: 0x0000,
		TimeToLive:     0x04,
		NextProtoID:    0x06,
		HdrChecksum:    0x7a74,
		SrcAddr:        0x0100007f,
		DstAddr:        0x05090980,
	},
	{
		VersionIhl:     0x45,
		TypeOfService:  0x00,
		TotalLength:    0x2e00,
		PacketID:       0xfdbf,
		FragmentOffset: 0x0000,
		TimeToLive:     0x04,
		NextProtoID:    0x06,
		HdrChecksum:    0x7a74,
		SrcAddr:        0x0000007f,
		DstAddr:        0xff090980,
	},
	{
		VersionIhl:     0x45,
		TypeOfService:  0x00,
		TotalLength:    0x2e00,
		PacketID:       0xfdbf,
		FragmentOffset: 0x0000,
		TimeToLive:     0x04,
		NextProtoID:    0x11,
		HdrChecksum:    0x7a74,
		SrcAddr:        0x0000007f,
		DstAddr:        0xff090980,
	},
	{
		VersionIhl:     0x45,
		TypeOfService:  0x00,
		TotalLength:    0x2e00,
		PacketID:       0xfdbf,
		FragmentOffset: 0x0000,
		TimeToLive:     0x04,
		NextProtoID:    0x06,
		HdrChecksum:    0x7a74,
		SrcAddr:        0xff00007f,
		DstAddr:        0x05090980,
	},
	{
		VersionIhl:     0x45,
		TypeOfService:  0x00,
		TotalLength:    0x2e00,
		PacketID:       0xfdbf,
		FragmentOffset: 0x0000,
		TimeToLive:     0x04,
		NextProtoID:    0x06,
		HdrChecksum:    0x7a74,
		SrcAddr:        0x78563412,
		DstAddr:        0x0f090980,
	},
	{
		VersionIhl:     0x45,
		TypeOfService:  0x00,
		TotalLength:    0x2e00,
		PacketID:       0xfdbf,
		FragmentOffset: 0x0000,
		TimeToLive:     0x04,
		NextProtoID:    0x11,
		HdrChecksum:    0x7a74,
		SrcAddr:        0x78563412,
		DstAddr:        0x14090980,
	},
	{
		VersionIhl:     0x45,
		TypeOfService:  0x00,
		TotalLength:    0x2e00,
		PacketID:       0xfdbf,
		FragmentOffset: 0x0000,
		TimeToLive:     0x04,
		NextProtoID:    0x06,
		HdrChecksum:    0x7a74,
		SrcAddr:        0x78563412,
		DstAddr:        0x14090980,
	},
}

var TCPHeader = [4]TCPHdr{
	{
		SrcPort:  0xd204,
		DstPort:  0x2e16,
		SentSeq:  0x78563412,
		RecvAck:  0x90563412,
		DataOff:  0x50,
		TCPFlags: 0x10,
		RxWin:    0x0020,
		Cksum:    0xe6ff,
		TCPUrp:   0x0000,
	},
	{
		SrcPort:  0xd204,
		DstPort:  0x2f16,
		SentSeq:  0x78563412,
		RecvAck:  0x90563412,
		DataOff:  0x50,
		TCPFlags: 0x10,
		RxWin:    0x0020,
		Cksum:    0xe6ff,
		TCPUrp:   0x0000,
	},
	{
		SrcPort:  0x3412,
		DstPort:  0x2f16,
		SentSeq:  0x78563412,
		RecvAck:  0x90563412,
		DataOff:  0x50,
		TCPFlags: 0x10,
		RxWin:    0x0020,
		Cksum:    0xe6ff,
		TCPUrp:   0x0000,
	},
	{
		SrcPort:  0x3412,
		DstPort:  0x7856,
		SentSeq:  0x78563412,
		RecvAck:  0x90563412,
		DataOff:  0x50,
		TCPFlags: 0x10,
		RxWin:    0x0020,
		Cksum:    0xe6ff,
		TCPUrp:   0x0000,
	},
}

var UDPHeader = [2]UDPHdr{
	{
		SrcPort:    0xd304,
		DstPort:    0x2f16,
		DgramLen:   0x4000,
		DgramCksum: 0x0000,
	},
	{
		SrcPort:    0xd204,
		DstPort:    0x0000,
		DgramLen:   0x4000,
		DgramCksum: 0x0000,
	},
}
var pkts = [8]Packet{
	{
		Ether:    &MacHeader[0],
		IPv4:     &IPHeader[0],
		IPv6:     nil,
		TCP:      &TCPHeader[0],
		UDP:      nil,
		Unparsed: 0,
	},
	{
		Ether:    &MacHeader[1],
		IPv4:     &IPHeader[1],
		IPv6:     nil,
		TCP:      &TCPHeader[1],
		UDP:      nil,
		Unparsed: 0,
	},
	{
		Ether:    &MacHeader[2],
		IPv4:     &IPHeader[2],
		IPv6:     nil,
		TCP:      nil,
		UDP:      &UDPHeader[0],
		Unparsed: 0,
	},
	{
		Ether:    &MacHeader[3],
		IPv4:     &IPHeader[3],
		IPv6:     nil,
		TCP:      &TCPHeader[2],
		UDP:      nil,
		Unparsed: 0,
	},
	{
		Ether:    &MacHeader[4],
		IPv4:     &IPHeader[4],
		IPv6:     nil,
		TCP:      &TCPHeader[3],
		UDP:      nil,
		Unparsed: 0,
	},
	{
		Ether:    &MacHeader[5],
		IPv4:     &IPHeader[5],
		IPv6:     nil,
		TCP:      nil,
		UDP:      &UDPHeader[1],
		Unparsed: 0,
	},
	{
		Ether:    &MacHeader[6],
		IPv4:     &IPHeader[6],
		IPv6:     nil,
		TCP:      &TCPHeader[3],
		UDP:      nil,
		Unparsed: 0,
	},
	{
		Ether:    &MacHeader[7],
		IPv4:     &IPHeader[5],
		IPv6:     nil,
		TCP:      nil,
		UDP:      &UDPHeader[1],
		Unparsed: 0,
	},
}

// TODO: these packets has no payload. Need to add tests with payload
var lines = []string{
	"00112233445501112131415108004500002ebffd00000406747a7f0000018009090504d2162e123456781234569050102000ffe60000",
	"00112233445501112131415108004500002ebffd00000406747a7f000000800909ff04d2162f123456781234569050102000ffe60000",
	"00112233445501112131415208004500002ebffd00000411747a7f000000800909ff04d3162f00400000",
	"00112233445501112131415208004500002ebffd00000406747a7f0000ff800909051234162f123456781234569050102000ffe60000",
	"00112233445501112131415208004500002ebffd00000406747a123456788009090f12345678123456781234569050102000ffe60000",
	"00122233445501112131415208004500002ebffd00000411747a123456788009091404d2000000400000",
	"10112233445501112131415108004500002ebffd00000406747a123456788009091412345678123456781234569050102000ffe60000",
	"00112233445501112131415108004500002ebffd00000411747a123456788009091404d2000000400000",
}

func TestParseL4(t *testing.T) {
	for i := 0; i < len(lines); i++ {
		decoded, _ := hex.DecodeString(lines[i])
		mb := make([]uintptr, 1)
		low.AllocateMbufs(mb)
		pkt := ExtractPacket(mb[0])
		PacketFromByte(pkt, decoded)
		if pkt == nil {
			t.Fatal("Unable to construct mbuf")
		}

		pkt.ParseL4()

		if !reflect.DeepEqual(pkt.Ether, pkts[i].Ether) {
			t.Errorf("Automatic parse all levels: packet %d: wrong Ether header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.Ether, pkts[i].Ether)
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.IPv4, pkts[i].IPv4) {
			t.Errorf("Automatic parse all levels: packet %d: wrong IPv4 header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.IPv4, pkts[i].IPv4)
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.UDP, pkts[i].UDP) {
			t.Errorf("Automatic parse all levels: packet %d: wrong UDP header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.UDP, pkts[i].UDP)
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.TCP, pkts[i].TCP) {
			t.Errorf("Automatic parse all levels: packet %d: wrong TCP header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.TCP, pkts[i].TCP)
			t.FailNow()
		}
	}
}

func TestParseEther(t *testing.T) {
	for i := 0; i < len(lines); i++ {
		decoded, _ := hex.DecodeString(lines[i])
		mb := make([]uintptr, 1)
		low.AllocateMbufs(mb)
		pkt := ExtractPacket(mb[0])
		PacketFromByte(pkt, decoded)

		pkt.ParseEther()

		if !reflect.DeepEqual(pkt.Ether, pkts[i].Ether) {
			t.Errorf("Parse ethernet: packet %d: wrong Ether header: \ngot: %+v, \nwant: %+v\n\n", i, pkt.Ether, pkts[i].Ether)
			t.FailNow()
		}
	}
}

func TestParseEtherIPv4(t *testing.T) {
	for i := 0; i < len(lines); i++ {
		decoded, _ := hex.DecodeString(lines[i])
		mb := make([]uintptr, 1)
		low.AllocateMbufs(mb)
		pkt := ExtractPacket(mb[0])
		PacketFromByte(pkt, decoded)

		pkt.ParseEtherIPv4()

		if !reflect.DeepEqual(pkt.Ether, pkts[i].Ether) {
			t.Errorf("Parse ethernet and IPv4: packet %d: wrong Ether header: \ngot: %+v, \nwant: %+v\n\n", i, pkt.Ether, pkts[i].Ether)
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.IPv4, pkts[i].IPv4) {
			t.Errorf("Parse ethernet and IPv4: packet %d: wrong IPv4 header: \ngot: %+v, \nwant: %+v\n\n", i, pkt.IPv4, pkts[i].IPv4)
			t.FailNow()
		}
	}
}

// Test ParseEtherIPv4UDP and ParseEtherIPv4TCP
func TestParseEtherIPv4_(t *testing.T) {
	for i := 0; i < len(lines); i++ {
		decoded, _ := hex.DecodeString(lines[i])
		mb := make([]uintptr, 1)
		low.AllocateMbufs(mb)
		pkt := ExtractPacket(mb[0])
		PacketFromByte(pkt, decoded)

		if i == 2 || i == 5 || i == 7 {
			pkt.ParseEtherIPv4UDP()
		} else {
			pkt.ParseEtherIPv4TCP()
		}

		if !reflect.DeepEqual(pkt.Ether, pkts[i].Ether) {
			t.Errorf("Parse ethernet, IP and TCP/UDP: packet %d: wrong Ether header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.Ether, pkts[i].Ether)
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.IPv4, pkts[i].IPv4) {
			t.Errorf("Parse ethernet, IP and TCP/UDP: packet %d: wrong IPv4 header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.IPv4, pkts[i].IPv4)
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.UDP, pkts[i].UDP) {
			t.Errorf("Parse ethernet, IP and TCP/UDP: packet %d: wrong UDP header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.UDP, pkts[i].UDP)
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.TCP, pkts[i].TCP) {
			t.Errorf("Parse ethernet, IP and TCP/UDP: packet %d: wrong TCP header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.TCP, pkts[i].TCP)
			t.FailNow()
		}
	}

}

// Tested functions:
// ParseEtherData
// ParseEtherIPv4Data
// ParseEtherIPv4TCPData
// ParseIPv4TCPData
// ParseL3Data
// ParseL4Data
// ParseTCPData
func TestParseEtherIPv4TCPDataFunctions(t *testing.T) {
	// Ether IPv4 TCP packet with payload gt_payload
	gt_payload := uint64(12345)
	buffer := "001122334455011121314151080045000030bffd00000406eebb7f0000018009090504d2162e123456781234569050102000621c00003930000000000000"
	decoded, _ := hex.DecodeString(buffer)
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	PacketFromByte(pkt, decoded)

	low.AllocateMbufs(mb)
	parsedPkt := ExtractPacket(mb[0])
	PacketFromByte(parsedPkt, decoded)
	parsedPkt.ParseEtherIPv4TCP()

	pkt.ParseEtherData()
	gotIpv4 := *(*IPv4Hdr)(pkt.Data)
	wantIpv4 := *(parsedPkt.IPv4)
	if gotIpv4 != wantIpv4 {
		t.Errorf("ParseIPv4TCPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseEtherIPv4Data()
	gotTcp := *(*TCPHdr)(pkt.Data)
	wantTcp := *(parsedPkt.TCP)
	if gotTcp != wantTcp {
		t.Errorf("ParseEtherIPv4Data incorrect result:\ngot:%x\nwant:%x\n", gotTcp, wantTcp)
	}
	clearPacket(pkt)

	pkt.ParseEtherIPv4TCPData()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseEtherIPv4TCPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseIPv4TCPData()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseIPv4TCPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseL3Data()
	gotTcp = *(*TCPHdr)(pkt.Data)
	wantTcp = *(parsedPkt.TCP)
	if gotTcp != wantTcp {
		t.Errorf("ParseL3Data incorrect result:\ngot:%x\nwant:%x\n", gotTcp, wantTcp)
	}
	clearPacket(pkt)

	pkt.ParseL4Data()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseL4Data incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseTCPData(EtherLen + IPv4MinLen)
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseTCPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
}

// Tested functions:
// ParseEtherIPv4UDPData
// ParseIPv4UDPData
// ParseL4Data
// ParseUDPData
func TestParseIPv4UDPDataFunctions(t *testing.T) {
	// IPv4 UDP packet with payload gt_payload
	gt_payload := uint64(12345)
	buffer := "001122334455011121314151080045000024bffd00000411eebc7f0000018009090504d2162e0010a38e393000000000000000000000000000000000"
	decoded, _ := hex.DecodeString(buffer)
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	PacketFromByte(pkt, decoded)

	pkt.ParseEtherIPv4UDPData()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseEtherIPv4UDPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseIPv4UDPData()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseIPv4UDPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseL4Data()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseL4Data incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseUDPData(EtherLen + IPv4MinLen)
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseUDPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
}

// Tested functions:
// ParseEtherIPv6Data
// ParseEtherIPv6TCPData
// ParseIPv6TCPData
// ParseL3Data
// ParseL4Data
// ParseTCPData
func TestParseIPv6TCPDataFunctions(t *testing.T) {
	// IPv6 TCP packet with payload gt_payload
	gt_payload := uint64(12345)
	buffer := "00112233445501112131415186dd60000000001c0600dead000000000000000000000000beafdead000000000000000000000000ddfd04d2162e123456781234569050102000102300003930000000000000"
	decoded, _ := hex.DecodeString(buffer)
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	PacketFromByte(pkt, decoded)

	low.AllocateMbufs(mb)
	parsedPkt := ExtractPacket(mb[0])
	PacketFromByte(parsedPkt, decoded)
	parsedPkt.ParseEtherIPv6TCP()

	pkt.ParseEtherIPv6Data()
	gotTcp := *(*TCPHdr)(pkt.Data)
	wantTcp := *(parsedPkt.TCP)
	if gotTcp != wantTcp {
		t.Errorf("ParseEtherIPv6Data incorrect result:\ngot:%x\nwant:%x\n", gotTcp, wantTcp)
	}
	clearPacket(pkt)

	pkt.ParseEtherIPv6TCPData()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseEtherIPv6TCPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseIPv6TCPData()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseIPv6TCPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseL3Data()
	gotTcp = *(*TCPHdr)(pkt.Data)
	wantTcp = *(parsedPkt.TCP)
	if gotTcp != wantTcp {
		t.Errorf("ParseL3Data incorrect result:\ngot:%x\nwant:%x\n", gotTcp, wantTcp)
	}
	clearPacket(pkt)

	pkt.ParseL4Data()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseL4Data incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseTCPData(EtherLen + IPv6Len)
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseTCPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
}

// Tested functions
// ParseEtherIPv6UDPData
// ParseIPv6UDPData
// ParseL4Data
// ParseUDPData
func TestParseIPv6UDPDataFunctions(t *testing.T) {
	// IPv6 UDP packet with payload gt_payload
	gt_payload := uint64(12345)
	buffer := "00112233445501112131415186dd6000000000101100dead000000000000000000000000beafdead000000000000000000000000ddfd04d2162e001051953930000000000000"
	decoded, _ := hex.DecodeString(buffer)
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	PacketFromByte(pkt, decoded)

	pkt.ParseEtherIPv6UDPData()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseEtherIPv6UDPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseIPv6UDPData()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseIPv6UDPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseL4Data()
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseL4Data incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
	clearPacket(pkt)

	pkt.ParseUDPData(EtherLen + IPv6Len)
	if *(*uint64)(pkt.Data) != gt_payload {
		t.Errorf("ParseUDPData incorrect result:\ngot:%x\nwant:%x\n", *(*uint64)(pkt.Data), gt_payload)
	}
}

func clearPacket(packet *Packet) {
	packet.Ether = nil
	packet.IPv4 = nil
	packet.IPv6 = nil
	packet.TCP = nil
	packet.UDP = nil
	packet.Data = nil
}

// Tested functions
// EncapsulateHead
// EncapsulateTail
// DecapsulateHead
// DecapsulateTail
// PacketBytesChange
func TestEncapsulationDecapsulationFunctions(t *testing.T) {
	init := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	add := []byte{30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49}

	mb := make([]uintptr, 1)

	for i := uint(0); i < 11; i++ {
		for j := uint(1); j < 21; j++ {
			low.AllocateMbufs(mb)
			pkt := ExtractPacket(mb[0])
			PacketFromByte(pkt, init)

			pkt.EncapsulateHead(i, j)
			pkt.PacketBytesChange(i, add[0:j])
			var temp []byte
			reference := append(append(append(temp, init[0:i]...), add[0:j]...), init[i:10]...)
			answer := pkt.GetRawPacketBytes()
			if !bytes.Equal(reference, answer) || pkt.GetPacketLen() != 10+j {
				t.Errorf("EncapsulateHead incorrect result i = %d, j = %d:\ngot:%d\nwant:%d\n", i, j, answer, reference)
			}

		}
	}
	for i := uint(0); i < 11; i++ {
		for j := uint(1); j < 21; j++ {
			low.AllocateMbufs(mb)
			pkt := ExtractPacket(mb[0])
			PacketFromByte(pkt, init)

			pkt.EncapsulateTail(i, j)
			pkt.PacketBytesChange(i, add[0:j])
			var temp []byte
			reference := append(append(append(temp, init[0:i]...), add[0:j]...), init[i:10]...)
			answer := pkt.GetRawPacketBytes()
			if !bytes.Equal(reference, answer) || pkt.GetPacketLen() != 10+j {
				t.Errorf("EncapsulateTail incorrect result i = %d, j = %d:\ngot:%d\nwant:%d\n", i, j, answer, reference)
			}

		}
	}
	for i := uint(0); i < 20; i++ {
		for j := uint(1); j < 20-i+1; j++ {
			low.AllocateMbufs(mb)
			pkt := ExtractPacket(mb[0])
			PacketFromByte(pkt, add)

			pkt.DecapsulateHead(i, j)
			var temp []byte
			reference := append(append(temp, add[0:i]...), add[i+j:20]...)
			answer := pkt.GetRawPacketBytes()
			if !bytes.Equal(reference, answer) || pkt.GetPacketLen() != 20-j {
				t.Errorf("DecapsulateHead incorrect result i = %d, j = %d:\ngot:%d\nwant:%d\n", i, j, answer, reference)
			}

		}
	}
	for i := uint(0); i < 20; i++ {
		for j := uint(1); j < 20-i+1; j++ {
			low.AllocateMbufs(mb)
			pkt := ExtractPacket(mb[0])
			PacketFromByte(pkt, add)

			pkt.DecapsulateTail(i, j)
			var temp []byte
			reference := append(append(temp, add[0:i]...), add[i+j:20]...)
			answer := pkt.GetRawPacketBytes()
			if !bytes.Equal(reference, answer) || pkt.GetPacketLen() != 20-j {
				t.Errorf("DecapsulateTail incorrect result i = %d, j = %d:\ngot:%d\nwant:%d\n", i, j, answer, reference)
			}

		}
	}
}

// These strings were created with gopacket library.
// gtLineIPv4 and gtLineIPv6 are cut after IP header, they are not complete packets.
var (
	testPlSize uint = 20

	gtLineEther = "0011223344550111213141510000"

	gtLineIPv4    = "00000000000000000000000008004500002800000000000000007f00000180090905"
	gtLineIPv4TCP = "0000000000000000000000000800450000280000000000060000000000000000000004d2162e00000000000000005000000000000000"
	gtLineIPv4UDP = "00000000000000000000000008004500001c0000000000110000000000000000000004d2162e00080000"

	gtLineIPv6    = "00000000000000000000000086dd6000000000140000dead000000000000000000000000beaf00000000000000000000000000000000"
	gtLineIPv6TCP = "00000000000000000000000086dd6000000000140600000000000000000000000000000000000000000000000000000000000000000004d2162e00000000000000005000000000000000"
	gtLineIPv6UDP = "00000000000000000000000086dd6000000000081100000000000000000000000000000000000000000000000000000000000000000004d2162e00080000"
)

func TestInitEmptyEtherPacket(t *testing.T) {
	// Create empty packet, set Ether header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	InitEmptyEtherPacket(pkt, 0)
	pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	pkt.Ether.SAddr = [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51}

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineEther)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb)
	gtPkt := ExtractPacket(gtMb[0])
	PacketFromByte(gtPkt, gtBuf)

	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.Unparsed))[:EtherLen]
	// DEEP equal for whole packet buffer
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyEtherIPv4Packet(t *testing.T) {
	// Create empty packet, set IPv4 header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	InitEmptyEtherIPv4Packet(pkt, testPlSize)
	dst := net.ParseIP("128.9.9.5").To4()
	src := net.ParseIP("127.0.0.1").To4()
	pkt.IPv4.DstAddr = binary.LittleEndian.Uint32([]byte(dst))
	pkt.IPv4.SrcAddr = binary.LittleEndian.Uint32([]byte(src))

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv4)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb)
	gtPkt := ExtractPacket(gtMb[0])
	PacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv4MinLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.Unparsed))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyEtherIPv6Packet(t *testing.T) {
	// Create empty packet, set IPv6 header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	InitEmptyEtherIPv6Packet(pkt, testPlSize)
	pkt.IPv6.SrcAddr = [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xaf}

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv6)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb)
	gtPkt := ExtractPacket(gtMb[0])
	PacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv6Len
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.Unparsed))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyEtherIPv4TCPPacket(t *testing.T) {
	// Create empty packet, set TCP header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	InitEmptyEtherIPv4TCPPacket(pkt, 0)
	pkt.TCP.DstPort = SwapBytesUint16(5678)
	pkt.TCP.SrcPort = SwapBytesUint16(1234)

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv4TCP)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb)
	gtPkt := ExtractPacket(gtMb[0])
	PacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv4MinLen + TCPMinLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.Unparsed))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyEtherIPv4UDPPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	InitEmptyEtherIPv4UDPPacket(pkt, 0)
	pkt.UDP.DstPort = SwapBytesUint16(5678)
	pkt.UDP.SrcPort = SwapBytesUint16(1234)

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv4UDP)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb)
	gtPkt := ExtractPacket(gtMb[0])
	PacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv4MinLen + UDPLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.Unparsed))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyEtherIPv6TCPPacket(t *testing.T) {
	// Create empty packet, set TCP header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	InitEmptyEtherIPv6TCPPacket(pkt, 0)
	pkt.TCP.DstPort = SwapBytesUint16(5678)
	pkt.TCP.SrcPort = SwapBytesUint16(1234)

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv6TCP)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb)
	gtPkt := ExtractPacket(gtMb[0])
	PacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv6Len + TCPMinLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.Unparsed))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyEtherIPv6UDPPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt := ExtractPacket(mb[0])
	InitEmptyEtherIPv6UDPPacket(pkt, 0)
	pkt.UDP.DstPort = SwapBytesUint16(5678)
	pkt.UDP.SrcPort = SwapBytesUint16(1234)

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv6UDP)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb)
	gtPkt := ExtractPacket(gtMb[0])
	PacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv6Len + UDPLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.Unparsed))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}

}
