// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"reflect"
	"testing"
	"unsafe"

	. "github.com/intel-go/yanff/common"
)

func init() {
	tInitDPDK()
}

var (
	// This string was created with gopacket library.
	gtLineIPv4TCPVLAN = "00400540ef240060089fb1f3810000200800450000288a1b00004006000083972015839720811770048a0000000100000d9550107c7000000000"

	MacHeaderVLAN = EtherHdr{
		DAddr:     [6]uint8{0x00, 0x40, 0x05, 0x40, 0xef, 0x24},
		SAddr:     [6]uint8{0x00, 0x60, 0x08, 0x9f, 0xb1, 0xf3},
		EtherType: SwapBytesUint16(VLANNumber),
	}

	VlanTag = VLANHdr{
		TCI:       SwapBytesUint16(32),
		EtherType: SwapBytesUint16(IPV4Number),
	}

	IPv4HeaderVLAN = IPv4Hdr{
		VersionIhl:  0x45,
		PacketID:    SwapBytesUint16(35355),
		TimeToLive:  uint8(64),
		NextProtoID: TCPNumber,
		HdrChecksum: 0,
		SrcAddr:     binary.LittleEndian.Uint32([]byte(net.ParseIP("131.151.32.21").To4())),
		DstAddr:     binary.LittleEndian.Uint32([]byte(net.ParseIP("131.151.32.129").To4())),
		TotalLength: SwapBytesUint16(uint16(IPv4MinLen + TCPMinLen)),
	}

	IPv6HeaderVLAN = IPv6Hdr{
		VtcFlow:   SwapBytesUint32(0x60 << 24),
		HopLimits: 255,
		Proto:     NoNextHeader,
		SrcAddr: [16]byte{0x26, 0x07, 0xf2, 0xc0, 0xf0, 0x0f,
			0xb0, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfa, 0xce, 0xb0, 0x0c},
		DstAddr: [16]byte{0x26, 0x07, 0xf2, 0xc0, 0xf0, 0x0f,
			0xb0, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfa, 0xce, 0xb0, 0x0c},
	}

	TCPHeaderVLAN = TCPHdr{
		SrcPort:  SwapBytesUint16(6000),
		DstPort:  SwapBytesUint16(1162),
		SentSeq:  SwapBytesUint32(1),
		RecvAck:  SwapBytesUint32(3477),
		TCPFlags: TCPFlagAck,
		RxWin:    SwapBytesUint16(31856),
		Cksum:    0,
		DataOff:  0x50,
	}

	ARPHeaderVLAN = ARPHdr{
		HType:     SwapBytesUint16(1),
		PType:     SwapBytesUint16(IPV4Number),
		HLen:      EtherAddrLen,
		PLen:      IPv4AddrLen,
		Operation: SwapBytesUint16(ARPRequest),
		SHA:       MacHeaderVLAN.SAddr,
		SPA:       IPv4ToBytes(IPv4HeaderVLAN.SrcAddr),
		THA:       [EtherAddrLen]uint8{},
		TPA:       IPv4ToBytes(IPv4HeaderVLAN.DstAddr),
	}
)

func initTestIPv4Packet(pkt *Packet) {
	InitEmptyIPv4TCPPacket(pkt, 0)
	pkt.Ether.DAddr = MacHeaderVLAN.DAddr
	pkt.Ether.SAddr = MacHeaderVLAN.SAddr
	pktIPv4 := pkt.GetIPv4()
	pktIPv4.DstAddr = IPv4HeaderVLAN.DstAddr
	pktIPv4.SrcAddr = IPv4HeaderVLAN.SrcAddr
	pktIPv4.PacketID = IPv4HeaderVLAN.PacketID
	pktIPv4.TimeToLive = IPv4HeaderVLAN.TimeToLive
	pktIPv4.HdrChecksum = IPv4HeaderVLAN.HdrChecksum
	pktTCP := pkt.GetTCPForIPv4()
	pktTCP.DstPort = TCPHeaderVLAN.DstPort
	pktTCP.SrcPort = TCPHeaderVLAN.SrcPort
	pktTCP.TCPFlags = TCPHeaderVLAN.TCPFlags
	pktTCP.SentSeq = TCPHeaderVLAN.SentSeq
	pktTCP.RecvAck = TCPHeaderVLAN.RecvAck
	pktTCP.RxWin = TCPHeaderVLAN.RxWin
	pktTCP.Cksum = TCPHeaderVLAN.Cksum
}

func initTestIPv6Packet(pkt *Packet) {
	InitEmptyIPv6Packet(pkt, 0)
	pkt.Ether.DAddr = MacHeaderVLAN.DAddr
	pkt.Ether.SAddr = MacHeaderVLAN.SAddr
	pktIPv6Hdr := pkt.GetIPv6()
	pktIPv6Hdr.DstAddr = IPv6HeaderVLAN.DstAddr
	pktIPv6Hdr.SrcAddr = IPv6HeaderVLAN.SrcAddr
	pktIPv6Hdr.HopLimits = IPv6HeaderVLAN.HopLimits
}

func TestAddVLANTag(t *testing.T) {
	pkt := getPacket()
	initTestIPv4Packet(pkt)
	pkt.AddVLANTag(32)

	// Create ground truth packet
	gtBuf, _ := hex.DecodeString(gtLineIPv4TCPVLAN)
	gtPkt := getPacket()
	GeneratePacketFromByte(gtPkt, gtBuf)

	size := EtherLen + VLANLen + IPv4MinLen + TCPMinLen
	buf := (*[1 << 30]byte)(unsafe.Pointer(pkt.StartAtOffset(0)))[:size]
	if !reflect.DeepEqual(buf, gtBuf) {
		t.Errorf("Incorrect result:\ngot:  %x, \nwant: %x\n\n", buf, gtBuf)
		t.FailNow()
	}
}

func TestGetSetVLANTagIdentifier(t *testing.T) {
	pkt := getPacket()
	InitEmptyPacket(pkt, 0)

	tci := uint16(0xFF00)
	vid := tci & 0x0FFF
	pkt.AddVLANTag(tci)
	vlan := pkt.GetVLAN()
	if vlan.GetVLANTagIdentifier() != vid {
		t.Errorf("Incorrect vlan vid after adding:\ngot:  %x, \nwant: %x\n\n",
			vlan.GetVLANTagIdentifier(), vid)
		t.FailNow()
	}
	if SwapBytesUint16(vlan.TCI) != tci {
		t.Errorf("Incorrect vlan tag after adding:\ngot:  %x, \nwant: %x\n\n",
			SwapBytesUint16(vlan.TCI), tci)
		t.FailNow()
	}
	tci = 0xF0FF
	vid = tci & 0x0FFF
	vlan.SetVLANTagIdentifier(vid)
	if vlan.GetVLANTagIdentifier() != vid {
		t.Errorf("Incorrect vlan vid after seting vid:\ngot:  %x, \nwant: %x\n\n",
			vlan.GetVLANTagIdentifier(), vid)
		t.FailNow()
	}
	if SwapBytesUint16(vlan.TCI) != tci {
		t.Errorf("Incorrect vlan tag after seting vid:\ngot:  %x, \nwant: %x\n\n",
			SwapBytesUint16(vlan.TCI), tci)
		t.FailNow()
	}
}

func TestGetEtherType(t *testing.T) {
	pkt := getPacket()
	InitEmptyIPv4Packet(pkt, 0)

	etherType := pkt.GetEtherType()
	if etherType != IPV4Number {
		t.Errorf("Incorrect GetEtherType result:\ngot:  %x, \nwant: %x\n\n",
			etherType, IPV4Number)
		t.FailNow()
	}

	pkt.AddVLANTag(12)

	etherType = pkt.GetEtherType()
	if etherType != IPV4Number {
		t.Errorf("Incorrect GetEtherType result after vlan add:\ngot:  %x, \nwant: %x\n\n",
			etherType, IPV4Number)
		t.FailNow()
	}
	etherType = SwapBytesUint16(pkt.Ether.EtherType)
	if etherType != VLANNumber {
		t.Errorf("Incorrect pkt.Ether.EtherType after vlan add:\ngot:  %x, \nwant: %x\n\n",
			etherType, VLANNumber)
		t.FailNow()
	}
}

func TestGetVLAN(t *testing.T) {
	pkt := getPacket()
	InitEmptyIPv4Packet(pkt, 0)

	vlan := pkt.GetVLAN()
	if vlan != nil {
		t.Errorf("Incorrect GetVLAN result: expected nil, got %x\n\n",
			vlan)
		t.FailNow()
	}

	pkt.AddVLANTag(32)

	vlan = pkt.GetVLAN()
	if !reflect.DeepEqual(vlan, (*VLANHdr)(&VlanTag)) {
		t.Errorf("Incorrect GetVLAN result after vlan add:\ngot:  %x, \nwant: %x\n\n",
			vlan, (*VLANHdr)(&VlanTag))
		t.FailNow()
	}

	vlan = pkt.GetVLANNoCheck()
	if !reflect.DeepEqual(vlan, (*VLANHdr)(&VlanTag)) {
		t.Errorf("Incorrect GetVLANNoCheck result after vlan add:\ngot:  %x, \nwant: %x\n\n",
			vlan, (*VLANHdr)(&VlanTag))
		t.FailNow()
	}
}

func TestParseL3CheckVLAN(t *testing.T) {
	decoded, _ := hex.DecodeString(gtLineIPv4TCPVLAN)
	pkt := getPacket()
	GeneratePacketFromByte(pkt, decoded)
	if pkt == nil {
		t.Fatal("Unable to construct mbuf")
	}

	vlan := pkt.ParseL3CheckVLAN()

	if !reflect.DeepEqual(pkt.Ether, (*EtherHdr)(&MacHeaderVLAN)) {
		t.Errorf("Automatic parse all levels: wrong Ether header:\ngot: %+v, \nwant: %+v\n\n",
			pkt.Ether, (*EtherHdr)(&MacHeaderVLAN))
		t.FailNow()
	}
	if !reflect.DeepEqual(vlan, (*VLANHdr)(&VlanTag)) {
		t.Errorf("Automatic parse all levels: wrong vlan header:\ngot: %+v, \nwant: %+v\n\n",
			vlan, (*VLANHdr)(&VlanTag))
		t.FailNow()
	}
}

func TestParseAllKnownL3CheckVLAN(t *testing.T) {
	decoded, _ := hex.DecodeString(gtLineIPv4TCPVLAN)
	pkt := getPacket()
	GeneratePacketFromByte(pkt, decoded)
	if pkt == nil {
		t.Fatal("Unable to construct mbuf")
	}

	ipV4, ipV6, arp := pkt.ParseAllKnownL3CheckVLAN()

	if ipV6 != nil || arp != nil {
		t.Errorf("Expected arp, ipv6 headers nil, ParseAllKnownL3CheckVLAN returned not nil")
		t.FailNow()
	}

	if !reflect.DeepEqual(pkt.GetIPv4CheckVLAN(), ipV4) {
		t.Errorf("GetIPv4CheckVLAN() and ParseAllKnownL3CheckVLAN() returned different ipv4 values")
		t.FailNow()
	}

	if !reflect.DeepEqual(pkt.Ether, (*EtherHdr)(&MacHeaderVLAN)) {
		t.Errorf("Automatic parse all levels: wrong Ether header:\ngot: %+v, \nwant: %+v\n\n",
			pkt.Ether, (*EtherHdr)(&MacHeaderVLAN))
		t.FailNow()
	}

	if !reflect.DeepEqual(pkt.GetIPv4CheckVLAN(), (*IPv4Hdr)(&IPv4HeaderVLAN)) {
		t.Errorf("Automatic parse all levels: wrong ipv4 header:\ngot: %+v, \nwant: %+v\n\n",
			pkt.GetIPv4CheckVLAN(), (*IPv4Hdr)(&IPv4HeaderVLAN))
		t.FailNow()
	}
}

func TestGetIPv4CheckVLAN(t *testing.T) {
	pkt := getPacket()
	initTestIPv4Packet(pkt)

	pktIPv4 := pkt.GetIPv4CheckVLAN()
	if !reflect.DeepEqual(pktIPv4, (*IPv4Hdr)(&IPv4HeaderVLAN)) {
		t.Errorf("GetIPv4CheckVLAN returned wrong walue:\ngot: %+v, \nwant: %+v\n\n",
			pktIPv4, (*IPv4Hdr)(&IPv4HeaderVLAN))
		t.FailNow()
	}

	pkt.AddVLANTag(32)

	pktIPv4 = pkt.GetIPv4CheckVLAN()
	if !reflect.DeepEqual(pktIPv4, (*IPv4Hdr)(&IPv4HeaderVLAN)) {
		t.Errorf("GetIPv4CheckVLAN returned wrong walue after vlan add:\ngot: %+v, \nwant: %+v\n\n",
			pktIPv4, (*IPv4Hdr)(&IPv4HeaderVLAN))
		t.FailNow()
	}
}

func TestGetIPv6CheckVLAN(t *testing.T) {
	pkt := getPacket()
	initTestIPv6Packet(pkt)

	pktIPv6 := pkt.GetIPv6CheckVLAN()
	if !reflect.DeepEqual(pktIPv6, (*IPv6Hdr)(&IPv6HeaderVLAN)) {
		t.Errorf("GetIPv6CheckVLAN returned wrong walue:\ngot: %+v, \nwant: %+v\n\n",
			pktIPv6, (*IPv6Hdr)(&IPv6HeaderVLAN))
		t.FailNow()
	}

	pkt.AddVLANTag(32)

	pktIPv6 = pkt.GetIPv6CheckVLAN()
	if !reflect.DeepEqual(pktIPv6, (*IPv6Hdr)(&IPv6HeaderVLAN)) {
		t.Errorf("GetIPv6CheckVLAN returned wrong walue after vlan add:\ngot: %+v, \nwant: %+v\n\n",
			pktIPv6, (*IPv6Hdr)(&IPv6HeaderVLAN))
		t.FailNow()
	}
}

func TestGetARPCheckVLAN(t *testing.T) {
	pkt := getPacket()
	InitARPRequestPacket(pkt, MacHeaderVLAN.SAddr, IPv4HeaderVLAN.SrcAddr, IPv4HeaderVLAN.DstAddr)

	pktARP := pkt.GetARPCheckVLAN()
	if !reflect.DeepEqual(pktARP, (*ARPHdr)(&ARPHeaderVLAN)) {
		t.Errorf("GetARPCheckVLAN returned wrong walue:\ngot: %+v, \nwant: %+v\n\n",
			pktARP, (*ARPHdr)(&ARPHeaderVLAN))
		t.FailNow()
	}

	pkt.AddVLANTag(32)

	pktARP = pkt.GetARPCheckVLAN()
	if !reflect.DeepEqual(pktARP, (*ARPHdr)(&ARPHeaderVLAN)) {
		t.Errorf("GetARPCheckVLAN returned wrong walue after vlan add:\ngot: %+v, \nwant: %+v\n\n",
			pktARP, (*ARPHdr)(&ARPHeaderVLAN))
		t.FailNow()
	}
}
