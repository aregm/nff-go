package stabilityCommon

import (
	"encoding/json"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"log"
	"net"
	"os"
)

var (
	config  map[string][]string
	dstMac0 [common.EtherAddrLen]uint8
	srcMac0 [common.EtherAddrLen]uint8
	dstMac1 [common.EtherAddrLen]uint8
	srcMac1 [common.EtherAddrLen]uint8
	stubMac = [common.EtherAddrLen]uint8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	// ModifyPacket is used to set src and dst MAC addresses for outgoing packets.
	ModifyPacket = []interface{}{modifyPacket0, modifyPacket1}
)

// ShouldBeSkipped return true for packets which are not expected to receive by test.
// Return false only for expected IPv4 UDP packets.
func ShouldBeSkipped(pkt *packet.Packet) bool {
	if packet.SwapBytesUint16(pkt.Ether.EtherType) != common.IPV4Number {
		println("Not IPv4 packet, skip")
		return true
	}
	pkt.ParseL3()
	pkt.ParseL4ForIPv4()
	if pkt.GetUDPForIPv4() == nil {
		println("Not UDP packet, skip")
		return true
	}
	if packet.SwapBytesUint16(pkt.GetUDPForIPv4().DstPort) == uint16(5353) {
		println("MDNS protocol over UDP, skip")
		return true
	}
	return false
}

// ProtocolType used to determine which protocols should not
// be skipped.
type ProtocolType uint

const (
	// constants for different protocol types.
	TypeUdpTcpIcmp ProtocolType = iota
	TypeUdpTcp
	TypeTcp
	TypeUdp
	TypeIcmp
)

// ShouldBeSkippedAllExcept return false for packets with given ip version and protocol type
// and true for all other. Specify 0 ip version to accept both 4 and 6.
func ShouldBeSkippedAllExcept(pkt *packet.Packet, ipVersion uint, protocol ProtocolType) bool {
	var pktTCP *packet.TCPHdr
	var pktUDP *packet.UDPHdr
	var pktICMP *packet.ICMPHdr
	pktIPv4, pktIPv6, _ := pkt.ParseAllKnownL3CheckVLAN()
	if (ipVersion == 0 || ipVersion == 4) && pktIPv4 != nil {
		pktTCP, pktUDP, pktICMP = pkt.ParseAllKnownL4ForIPv4()
	} else if (ipVersion == 0 || ipVersion == 6) && pktIPv6 != nil {
		pktTCP, pktUDP, pktICMP = pkt.ParseAllKnownL4ForIPv6()
	}
	if pktTCP != nil {
		switch protocol {
		case TypeTcp, TypeUdpTcpIcmp, TypeUdpTcp:
			return false
		}
	} else if pktUDP != nil {
		switch protocol {
		case TypeUdp, TypeUdpTcpIcmp, TypeUdpTcp:
			return false
		}
	} else if pktICMP != nil {
		switch protocol {
		case TypeIcmp, TypeUdpTcpIcmp:
			return false
		}
	}
	return true
}

// readConfig function reads and parses config file
func readConfig(fileName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(file)

	err = decoder.Decode(&config)
	if err != nil {
		return err
	}

	return nil
}

func printMAC(prompt string, mac [common.EtherAddrLen]uint8) {
	log.Printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", prompt, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// InitCommonState initializes src and dst MAC addesses to be set in outgoing packets.
func InitCommonState(configFile, target string) {
	// Get source MAC addresses for port 0 and 1
	srcMac0 = flow.GetPortMACAddress(0)
	printMAC("Source MAC 0", srcMac0)
	srcMac1 = flow.GetPortMACAddress(1)
	printMAC("Source MAC 1", srcMac1)

	if configFile != "" {
		// Read config
		err := readConfig(configFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Println("No config file specified, stub destination MAC addresses will be used")
		copy(dstMac0[:], stubMac[:])
		copy(dstMac1[:], stubMac[:])
		return
	}

	// Get destination MAC addressess for port 0 and 1 from config file
	if hw, err := net.ParseMAC(config[target][0]); err == nil {
		copy(dstMac0[:], hw)
	} else {
		log.Fatal(err)
	}
	printMAC("Destination MAC 0", dstMac0)
	if hw, err := net.ParseMAC(config[target][1]); err == nil {
		copy(dstMac1[:], hw)
	} else {
		log.Fatal(err)
	}
	printMAC("Destination MAC 1", dstMac1)
}

func modifyPacket0(pkt *packet.Packet, ctx flow.UserContext) {
	pkt.Ether.DAddr = dstMac0
	pkt.Ether.SAddr = srcMac0
}

func modifyPacket1(pkt *packet.Packet, ctx flow.UserContext) {
	pkt.Ether.DAddr = dstMac1
	pkt.Ether.SAddr = srcMac1
}
