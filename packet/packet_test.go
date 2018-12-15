// Copyright 2017-2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"encoding/hex"
	"net"
	"reflect"
	"testing"
	"unsafe"

	. "github.com/intel-go/nff-go/common"
)

func init() {
	tInitDPDK()
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
		Ether: &MacHeader[0],
		L3:    unsafe.Pointer(&IPHeader[0]),
		L4:    unsafe.Pointer(&TCPHeader[0]),
	},
	{
		Ether: &MacHeader[1],
		L3:    unsafe.Pointer(&IPHeader[1]),
		L4:    unsafe.Pointer(&TCPHeader[1]),
	},
	{
		Ether: &MacHeader[2],
		L3:    unsafe.Pointer(&IPHeader[2]),
		L4:    unsafe.Pointer(&UDPHeader[0]),
	},
	{
		Ether: &MacHeader[3],
		L3:    unsafe.Pointer(&IPHeader[3]),
		L4:    unsafe.Pointer(&TCPHeader[2]),
	},
	{
		Ether: &MacHeader[4],
		L3:    unsafe.Pointer(&IPHeader[4]),
		L4:    unsafe.Pointer(&TCPHeader[3]),
	},
	{
		Ether: &MacHeader[5],
		L3:    unsafe.Pointer(&IPHeader[5]),
		L4:    unsafe.Pointer(&UDPHeader[1]),
	},
	{
		Ether: &MacHeader[6],
		L3:    unsafe.Pointer(&IPHeader[6]),
		L4:    unsafe.Pointer(&TCPHeader[3]),
	},
	{
		Ether: &MacHeader[7],
		L3:    unsafe.Pointer(&IPHeader[5]),
		L4:    unsafe.Pointer(&UDPHeader[1]),
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

func TestParseL3(t *testing.T) {
	for i := 0; i < len(lines); i++ {
		decoded, _ := hex.DecodeString(lines[i])
		pkt := getPacket()
		GeneratePacketFromByte(pkt, decoded)
		if pkt == nil {
			t.Fatal("Unable to construct mbuf")
		}

		_, _, _ = pkt.ParseAllKnownL3()

		if !reflect.DeepEqual(pkt.Ether, pkts[i].Ether) {
			t.Errorf("Automatic parse all levels: packet %d: wrong Ether header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.Ether, pkts[i].Ether)
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.GetIPv4(), pkts[i].GetIPv4()) {
			t.Errorf("Automatic parse all levels: packet %d: wrong IPv4 header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.GetIPv4(), pkts[i].GetIPv4())
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.GetIPv6(), pkts[i].GetIPv6()) {
			t.Errorf("Automatic parse all levels: packet %d: wrong IPv6 header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.GetIPv6(), pkts[i].GetIPv6())
			t.FailNow()
		}
	}
}

func TestParseL4(t *testing.T) {
	for i := 0; i < len(lines); i++ {
		decoded, _ := hex.DecodeString(lines[i])
		pkt := getPacket()
		GeneratePacketFromByte(pkt, decoded)

		ipv4, ipv6, _ := pkt.ParseAllKnownL3()
		if ipv4 != nil {
			pkt.ParseAllKnownL4ForIPv4()
		} else if ipv6 != nil {
			pkt.ParseAllKnownL4ForIPv6()
		}

		if !reflect.DeepEqual(pkt.Ether, pkts[i].Ether) {
			t.Errorf("Automatic parse all levels: packet %d: wrong Ether header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.Ether, pkts[i].Ether)
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.GetIPv4(), pkts[i].GetIPv4()) {
			t.Errorf("Automatic parse all levels: packet %d: wrong IPv4 header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.GetIPv4(), pkts[i].GetIPv4())
			t.FailNow()
		}
		if !reflect.DeepEqual(pkt.GetIPv6(), pkts[i].GetIPv6()) {
			t.Errorf("Automatic parse all levels: packet %d: wrong IPv6 header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.GetIPv6(), pkts[i].GetIPv6())
			t.FailNow()
		}
		if ipv4 != nil && !reflect.DeepEqual(pkt.GetTCPForIPv4(), pkts[i].GetTCPForIPv4()) {
			t.Errorf("Automatic parse all levels: packet %d: wrong UDP header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.GetTCPForIPv4(), pkts[i].GetTCPForIPv4())
			t.FailNow()
		}
		if ipv6 != nil && !reflect.DeepEqual(pkt.GetTCPForIPv6(), pkts[i].GetTCPForIPv6()) {
			t.Errorf("Automatic parse all levels: packet %d: wrong UDP header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.GetTCPForIPv6(), pkts[i].GetTCPForIPv6())
			t.FailNow()
		}

		if ipv4 != nil && !reflect.DeepEqual(pkt.GetUDPForIPv4(), pkts[i].GetUDPForIPv4()) {
			t.Errorf("Automatic parse all levels: packet %d: wrong UDP header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.GetUDPForIPv4(), pkts[i].GetUDPForIPv4())
			t.FailNow()
		}
		if ipv6 != nil && !reflect.DeepEqual(pkt.GetUDPForIPv6(), pkts[i].GetUDPForIPv6()) {
			t.Errorf("Automatic parse all levels: packet %d: wrong UDP header:\ngot: %+v, \nwant: %+v\n\n", i, pkt.GetUDPForIPv6(), pkts[i].GetUDPForIPv6())
			t.FailNow()
		}
	}
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

	for i := uint(0); i < 11; i++ {
		for j := uint(1); j < 21; j++ {
			pkt := getPacket()
			GeneratePacketFromByte(pkt, init)

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
			pkt := getPacket()
			GeneratePacketFromByte(pkt, init)

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
			pkt := getPacket()
			GeneratePacketFromByte(pkt, add)

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
			pkt := getPacket()
			GeneratePacketFromByte(pkt, add)

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

type Packetdata struct {
	F1, F2 uint32
}

// These strings were created with gopacket library.
// gtLineIPv4 and gtLineIPv6 are not complete and correctly formed packets: right after L3 goes some packet data, not L4.
var (
	testPlSize uint = uint(unsafe.Sizeof(*new(Packetdata)))

	gtLineEther = "0011223344550111213141510000"

	gtLineIPv4    = "00000000000000000000000008004500001c00000000403b00007f00000180090905ffdd0000bbaa0000"
	gtLineIPv4TCP = "0000000000000000000000000800450000300000000040060000000000000000000004d2162e00000000000000005000000000000000ffdd0000bbaa0000"
	gtLineIPv4UDP = "0000000000000000000000000800450000240000000040110000000000000000000004d2162e00100000ffdd0000bbaa0000"

	gtLineIPv6    = "00000000000000000000000086dd6000000000083bffdead000000000000000000000000beef00000000000000000000000000000000ffdd0000bbaa0000"
	gtLineIPv6TCP = "00000000000000000000000086dd60000000001406ff000000000000000000000000000000000000000000000000000000000000000004d2162e00000000000000005000000000000000ffdd0000bbaa0000"
	gtLineIPv6UDP = "00000000000000000000000086dd60000000001011ff000000000000000000000000000000000000000000000000000000000000000004d2162e00100000ffdd0000bbaa0000"
)

func TestInitEmptyPacket(t *testing.T) {
	// Create empty packet, set Ether header fields
	pkt := getPacket()
	InitEmptyPacket(pkt, 0)
	pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	pkt.Ether.SAddr = [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51}

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineEther)

	gtPkt := getPacket()
	GeneratePacketFromByte(gtPkt, gtBuf)

	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:EtherLen]
	// DEEP equal for whole packet buffer
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv4Packet(t *testing.T) {
	// Create empty packet, set IPv4 header fields
	pkt := getPacket()
	InitEmptyIPv4Packet(pkt, testPlSize)
	dst := net.ParseIP("128.9.9.5").To4()
	src := net.ParseIP("127.0.0.1").To4()
	pkt.GetIPv4().DstAddr = SliceToIPv4(dst)
	pkt.GetIPv4().SrcAddr = SliceToIPv4(src)
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv4)

	gtPkt := getPacket()
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv4MinLen + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv6Packet(t *testing.T) {
	// Create empty packet, set IPv6 header fields
	pkt := getPacket()
	InitEmptyIPv6Packet(pkt, testPlSize)
	pkt.GetIPv6().SrcAddr = [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xef}
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv6)
	gtPkt := getPacket()
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv6Len + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv4TCPPacket(t *testing.T) {
	// Create empty packet, set TCP header fields
	pkt := getPacket()
	InitEmptyIPv4TCPPacket(pkt, testPlSize)
	pkt.GetTCPForIPv4().DstPort = SwapBytesUint16(5678)
	pkt.GetTCPForIPv4().SrcPort = SwapBytesUint16(1234)
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv4TCP)
	gtPkt := getPacket()
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv4MinLen + TCPMinLen + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv4UDPPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	pkt := getPacket()
	InitEmptyIPv4UDPPacket(pkt, testPlSize)
	pkt.GetUDPForIPv4().DstPort = SwapBytesUint16(5678)
	pkt.GetUDPForIPv4().SrcPort = SwapBytesUint16(1234)
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv4UDP)
	gtPkt := getPacket()
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv4MinLen + UDPLen + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv6TCPPacket(t *testing.T) {
	// Create empty packet, set TCP header fields
	pkt := getPacket()
	InitEmptyIPv6TCPPacket(pkt, 0)
	pkt.GetTCPForIPv6().DstPort = SwapBytesUint16(5678)
	pkt.GetTCPForIPv6().SrcPort = SwapBytesUint16(1234)
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv6TCP)
	gtPkt := getPacket()
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv6Len + TCPMinLen + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv6UDPPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	pkt := getPacket()
	InitEmptyIPv6UDPPacket(pkt, testPlSize)
	pkt.GetUDPForIPv6().DstPort = SwapBytesUint16(5678)
	pkt.GetUDPForIPv6().SrcPort = SwapBytesUint16(1234)
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv6UDP)
	gtPkt := getPacket()
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv6Len + UDPLen + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}

}

func TestGetPacketPayload(t *testing.T) {
	// Test packets resources: http://wiresharkbook.com/studyguide.html
	// and https://wiki.wireshark.org/SampleCaptures
	table := []plTest{
		{
			name:    "IPv4-TCP",
			header:  "00015c31bbc1d48564a7bfa308004500003417244000800600001806addc45abe427fe61005018a91ba50000000080022000efdb0000020405b40103030201010402",
			payload: "",
			status:  true,
		},
		{
			name:    "IPv6-UDP",
			header:  "333300010003001b9e70104286dd60000000001e1101fe80000000000000ddbbe7d2c6d4a0f5ff020000000000000000000000010003f43b14eb001e4748",
			payload: "a4b600000001000000000000044461647a0000010001",
			status:  true,
		},
		{
			name:    "IPv4-UDP",
			header:  "00015c31bbc1d48564a7bfa308004500003e17210000801100001806addc44574cb6ed9b0035002a572b",
			payload: "dac301000001000000000000037777770866616365626f6f6b03636f6d0000010001",
			status:  true,
		},
		{
			name:    "IPv4-ICMP",
			header:  "00901a4277100018ded027d708004500005c6085000008013d755065ed55985b3e910800f7e800010016",
			payload: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			status:  true,
		},
		{
			name:    "IPv6-ICMPv6",
			header:  "3333ffc8e5c80018ded027d786dd6000000000183aff00000000000000000000000000000000ff0200000000000000000001ffc8e5c887008de800000000",
			payload: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			status:  true,
		},
		{
			name:    "IPv4-SCTP (unsupported)",
			header:  "0800034a003500a080005e4608004500003009d94000ff8450e20a1c062c0a1c062b0b804000214415232bf2024e03000010280243450000200000000000",
			payload: "",
			status:  false,
		},
	}

	for _, test := range table {
		fullpacket := test.header + test.payload
		buf, _ := hex.DecodeString(fullpacket)
		pkt := getPacket()
		GeneratePacketFromByte(pkt, buf)
		pl, status := pkt.GetPacketPayload()

		gtPl, _ := hex.DecodeString(test.payload)

		if !reflect.DeepEqual(pl, gtPl) {
			t.Errorf("Test %s: Incorrect payload:\ngot:  %x, \nwant: %x\n\n", test.name, pl, gtPl)
		}
		if status != test.status {
			t.Errorf("Test %s: Incorrect status:\ngot:  %v, \nwant: %v\n\n", test.name, status, test.status)
		}
	}
}

type plTest struct {
	name    string
	header  string
	payload string
	status  bool
}
