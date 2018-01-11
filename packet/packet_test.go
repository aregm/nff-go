// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"reflect"
	"testing"
	"unsafe"

	. "github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
	. "github.com/intel-go/yanff/packet"
)

var mempool *low.Mempool

func init() {
	mempool = GetMempoolForTest()
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
		mb := make([]uintptr, 1)
		if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
			log.Fatal(err)
		}
		pkt := ExtractPacket(mb[0])
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
		mb := make([]uintptr, 1)
		if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
			log.Fatal(err)
		}
		pkt := ExtractPacket(mb[0])
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

	mb := make([]uintptr, 1)

	for i := uint(0); i < 11; i++ {
		for j := uint(1); j < 21; j++ {
			if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
				log.Fatal(err)
			}
			pkt := ExtractPacket(mb[0])
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
			if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
				log.Fatal(err)
			}
			pkt := ExtractPacket(mb[0])
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
			if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
				log.Fatal(err)
			}
			pkt := ExtractPacket(mb[0])
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
			if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
				log.Fatal(err)
			}
			pkt := ExtractPacket(mb[0])
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

	gtLineIPv4    = "00000000000000000000000008004500001c00000000003b00007f00000180090905ffdd0000bbaa0000"
	gtLineIPv4TCP = "0000000000000000000000000800450000300000000000060000000000000000000004d2162e00000000000000005000000000000000ffdd0000bbaa0000"
	gtLineIPv4UDP = "0000000000000000000000000800450000240000000000110000000000000000000004d2162e00100000ffdd0000bbaa0000"

	gtLineIPv6    = "00000000000000000000000086dd6000000000083b00dead000000000000000000000000beaf00000000000000000000000000000000ffdd0000bbaa0000"
	gtLineIPv6TCP = "00000000000000000000000086dd6000000000140600000000000000000000000000000000000000000000000000000000000000000004d2162e00000000000000005000000000000000ffdd0000bbaa0000"
	gtLineIPv6UDP = "00000000000000000000000086dd6000000000101100000000000000000000000000000000000000000000000000000000000000000004d2162e00100000ffdd0000bbaa0000"
)

func TestInitEmptyPacket(t *testing.T) {
	// Create empty packet, set Ether header fields
	mb := make([]uintptr, 1)
	if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	pkt := ExtractPacket(mb[0])
	InitEmptyPacket(pkt, 0)
	pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	pkt.Ether.SAddr = [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51}

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineEther)

	gtMb := make([]uintptr, 1)
	if err := low.AllocateMbufs(gtMb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:EtherLen]
	// DEEP equal for whole packet buffer
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv4Packet(t *testing.T) {
	// Create empty packet, set IPv4 header fields
	mb := make([]uintptr, 1)
	if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	pkt := ExtractPacket(mb[0])
	InitEmptyIPv4Packet(pkt, testPlSize)
	dst := net.ParseIP("128.9.9.5").To4()
	src := net.ParseIP("127.0.0.1").To4()
	pkt.GetIPv4().DstAddr = binary.LittleEndian.Uint32([]byte(dst))
	pkt.GetIPv4().SrcAddr = binary.LittleEndian.Uint32([]byte(src))
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv4)

	gtMb := make([]uintptr, 1)
	if err := low.AllocateMbufs(gtMb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv4MinLen + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv6Packet(t *testing.T) {
	// Create empty packet, set IPv6 header fields
	mb := make([]uintptr, 1)
	if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	pkt := ExtractPacket(mb[0])
	InitEmptyIPv6Packet(pkt, testPlSize)
	pkt.GetIPv6().SrcAddr = [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xaf}
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv6)
	gtMb := make([]uintptr, 1)
	if err := low.AllocateMbufs(gtMb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv6Len + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv4TCPPacket(t *testing.T) {
	// Create empty packet, set TCP header fields
	mb := make([]uintptr, 1)
	if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	pkt := ExtractPacket(mb[0])
	InitEmptyIPv4TCPPacket(pkt, testPlSize)
	pkt.GetTCPForIPv4().DstPort = SwapBytesUint16(5678)
	pkt.GetTCPForIPv4().SrcPort = SwapBytesUint16(1234)
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv4TCP)
	gtMb := make([]uintptr, 1)
	if err := low.AllocateMbufs(gtMb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv4MinLen + TCPMinLen + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv4UDPPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	mb := make([]uintptr, 1)
	if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	pkt := ExtractPacket(mb[0])
	InitEmptyIPv4UDPPacket(pkt, testPlSize)
	pkt.GetUDPForIPv4().DstPort = SwapBytesUint16(5678)
	pkt.GetUDPForIPv4().SrcPort = SwapBytesUint16(1234)
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv4UDP)
	gtMb := make([]uintptr, 1)
	if err := low.AllocateMbufs(gtMb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv4MinLen + UDPLen + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv6TCPPacket(t *testing.T) {
	// Create empty packet, set TCP header fields
	mb := make([]uintptr, 1)
	if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	pkt := ExtractPacket(mb[0])
	InitEmptyIPv6TCPPacket(pkt, 0)
	pkt.GetTCPForIPv6().DstPort = SwapBytesUint16(5678)
	pkt.GetTCPForIPv6().SrcPort = SwapBytesUint16(1234)
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv6TCP)
	gtMb := make([]uintptr, 1)
	if err := low.AllocateMbufs(gtMb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv6Len + TCPMinLen + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyIPv6UDPPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	mb := make([]uintptr, 1)
	if err := low.AllocateMbufs(mb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	pkt := ExtractPacket(mb[0])
	InitEmptyIPv6UDPPacket(pkt, testPlSize)
	pkt.GetUDPForIPv6().DstPort = SwapBytesUint16(5678)
	pkt.GetUDPForIPv6().SrcPort = SwapBytesUint16(1234)
	ptrData := (*Packetdata)(pkt.Data)
	ptrData.F1 = 0xddff
	ptrData.F2 = 0xaabb

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv6UDP)
	gtMb := make([]uintptr, 1)
	if err := low.AllocateMbufs(gtMb, mempool, 1); err != nil {
		log.Fatal(err)
	}
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + IPv6Len + UDPLen + testPlSize
	buf := (*[1 << 30]byte)(pkt.StartAtOffset(0))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}

}
