// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/hex"
	"net"
	"reflect"
	"testing"
	"unsafe"

	. "github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
)

var mempoolARPTest *low.Mempool

func init() {
	mempoolARPTest = GetMempoolForTest()
}

// These strings were created with gopacket library.
var (
	gtLineARPRequest     = "ffffffffffff00070daff4540806000108000604000100070daff45418a6ac0100000000000018a6ad9f"
	gtLineARPReply       = "c40132580000c402326b000008060001080006040002c402326b00000a000002c401325800000a000001"
	gtLineGratARPRequest = "ffffffffffff02020202020208060001080006040001020202020202c0a80101000000000000c0a80101"
	gtLineGratARPReply   = "ffffffffffff00000c07ac010806000108000604000200000c07ac010a0000060000000000000a000006"
	gtLineEmptyARP       = "000000000000000000000000080600000000000000000000000000000000000000000000000000000000"
)

func TestInitARPCommonDataacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb, mempoolARPTest, 1)
	pkt := ExtractPacket(mb[0])

	initARPCommonData(pkt)
	pkt.Ether.DAddr = [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	pkt.Ether.SAddr = [6]uint8{0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54}
	pktARP := pkt.GetARP()
	pktARP.Operation = SwapBytesUint16(1)
	pktARP.SHA = [6]uint8{0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54}
	pktARP.THA = [6]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	copy(pktARP.SPA[:], net.ParseIP("24.166.172.1").To4()[:])
	copy(pktARP.TPA[:], net.ParseIP("24.166.173.159").To4()[:])

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineARPRequest)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb, mempoolARPTest, 1)
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + ARPLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.StartAtOffset(0)))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitARPRequestPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb, mempoolARPTest, 1)
	pkt := ExtractPacket(mb[0])
	sha := [6]uint8{0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54}
	srcIP := net.ParseIP("24.166.172.1").To4()
	dstIP := net.ParseIP("24.166.173.159").To4()
	spa := BytesToIPv4(srcIP[0], srcIP[1], srcIP[2], srcIP[3])
	tpa := BytesToIPv4(dstIP[0], dstIP[1], dstIP[2], dstIP[3])
	InitARPRequestPacket(pkt, sha, spa, tpa)

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineARPRequest)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb, mempoolARPTest, 1)
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + ARPLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.StartAtOffset(0)))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitARPReplyPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb, mempoolARPTest, 1)
	pkt := ExtractPacket(mb[0])
	tha := [6]uint8{0xc4, 0x01, 0x32, 0x58, 0x00, 0x00}
	sha := [6]uint8{0xc4, 0x02, 0x32, 0x6b, 0x00, 0x00}
	srcIP := net.ParseIP("10.0.0.2").To4()
	dstIP := net.ParseIP("10.0.0.1").To4()
	spa := BytesToIPv4(srcIP[0], srcIP[1], srcIP[2], srcIP[3])
	tpa := BytesToIPv4(dstIP[0], dstIP[1], dstIP[2], dstIP[3])
	InitARPReplyPacket(pkt, sha, tha, spa, tpa)

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineARPReply)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb, mempoolARPTest, 1)
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + ARPLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.StartAtOffset(0)))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitGARPAnnouncementRequestPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb, mempoolARPTest, 1)
	pkt := ExtractPacket(mb[0])
	sha := [6]uint8{0x02, 0x02, 0x02, 0x02, 0x02, 0x02}
	srcIP := net.ParseIP("192.168.1.1").To4()
	spa := BytesToIPv4(srcIP[0], srcIP[1], srcIP[2], srcIP[3])

	InitGARPAnnouncementRequestPacket(pkt, sha, spa)

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineGratARPRequest)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb, mempoolARPTest, 1)
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + ARPLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.StartAtOffset(0)))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitGARPAnnouncementReplyPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb, mempoolARPTest, 1)
	pkt := ExtractPacket(mb[0])
	sha := [6]uint8{0x00, 0x00, 0x0c, 0x07, 0xac, 0x01}
	srcIP := net.ParseIP("10.0.0.6").To4()
	spa := BytesToIPv4(srcIP[0], srcIP[1], srcIP[2], srcIP[3])

	InitGARPAnnouncementReplyPacket(pkt, sha, spa)

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineGratARPReply)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb, mempoolARPTest, 1)
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + ARPLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.StartAtOffset(0)))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}

func TestInitEmptyARPPacket(t *testing.T) {
	// Create empty packet, set UDP header fields
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb, mempoolARPTest, 1)
	pkt := ExtractPacket(mb[0])
	InitEmptyARPPacket(pkt)
	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineEmptyARP)
	gtMb := make([]uintptr, 1)
	low.AllocateMbufs(gtMb, mempoolARPTest, 1)
	gtPkt := ExtractPacket(gtMb[0])
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + ARPLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.StartAtOffset(0)))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
	}
}
