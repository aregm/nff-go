// +build !test

package packet

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
)

// isInit is common for all tests
var isInit bool

const payloadSize = 100

func tInitDPDK() {
	if isInit != true {
		argc, argv := low.InitDPDKArguments([]string{})
		// burstSize=32, mbufNumber=8191, mbufCacheSize=250
		low.InitDPDK(argc, argv, 32, 8191, 250, 0)
		nonPerfMempool = low.CreateMempool()
		isInit = true
	}
}

func getIPv4TCPTestPacket() *Packet {
	pkt := getPacket()
	InitEmptyIPv4TCPPacket(pkt, payloadSize)

	initEtherAddrs(pkt)
	initIPv4Addrs(pkt)
	initPorts(pkt)

	return pkt
}

func getIPv4UDPTestPacket() *Packet {
	pkt := getPacket()
	InitEmptyIPv4UDPPacket(pkt, payloadSize)

	initEtherAddrs(pkt)
	initIPv4Addrs(pkt)
	initPorts(pkt)

	return pkt
}

func getIPv4ICMPTestPacket() *Packet {
	pkt := getPacket()
	InitEmptyIPv4ICMPPacket(pkt, payloadSize)

	initEtherAddrs(pkt)
	initIPv4Addrs(pkt)

	return pkt
}

func getIPv6TCPTestPacket() *Packet {
	pkt := getPacket()
	InitEmptyIPv6TCPPacket(pkt, payloadSize)

	initEtherAddrs(pkt)
	initIPv6Addrs(pkt)
	initPorts(pkt)

	return pkt
}

func getIPv6UDPTestPacket() *Packet {
	pkt := getPacket()
	InitEmptyIPv6UDPPacket(pkt, payloadSize)

	initEtherAddrs(pkt)
	initIPv6Addrs(pkt)
	initPorts(pkt)
	return pkt
}

func getIPv6ICMPTestPacket() *Packet {
	pkt := getPacket()
	InitEmptyIPv6ICMPPacket(pkt, payloadSize)
	initEtherAddrs(pkt)
	initIPv6Addrs(pkt)

	return pkt
}

func getARPRequestTestPacket() *Packet {
	pkt := getPacket()

	sha := [common.EtherAddrLen]byte{0x01, 0x11, 0x21, 0x31, 0x41, 0x51}
	spa := binary.LittleEndian.Uint32(net.ParseIP("127.0.0.1").To4())
	tpa := binary.LittleEndian.Uint32(net.ParseIP("128.9.9.5").To4())
	InitARPRequestPacket(pkt, sha, spa, tpa)

	return pkt
}

func initEtherAddrs(pkt *Packet) {
	pkt.Ether.SAddr = [common.EtherAddrLen]byte{0x01, 0x11, 0x21, 0x31, 0x41, 0x51}
	pkt.Ether.DAddr = [common.EtherAddrLen]byte{0x0, 0x11, 0x22, 0x33, 0x44, 0x55}
}

func initIPv4Addrs(pkt *Packet) {
	pkt.GetIPv4().SrcAddr = binary.LittleEndian.Uint32(net.ParseIP("127.0.0.1").To4())
	pkt.GetIPv4().DstAddr = binary.LittleEndian.Uint32(net.ParseIP("128.9.9.5").To4())
}

func initIPv6Addrs(pkt *Packet) {
	copy(pkt.GetIPv6().SrcAddr[:], net.ParseIP("dead::beaf")[:common.IPv6AddrLen])
	copy(pkt.GetIPv6().DstAddr[:], net.ParseIP("dead::beaf")[:common.IPv6AddrLen])
}

func initPorts(pkt *Packet) {
	// Src and Dst port numbers placed at the same offset from L4 start in both tcp and udp
	l4 := (*UDPHdr)(pkt.L4)
	l4.SrcPort = SwapBytesUint16(1234)
	l4.DstPort = SwapBytesUint16(5678)
}

func getPacket() *Packet {
	pkt, err := NewPacket()
	if err != nil {
		log.Fatal(err)
	}
	return pkt
}
