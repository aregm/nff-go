package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var config map[string][]string
var dstMac0 [common.EtherAddrLen]uint8
var srcMac0 [common.EtherAddrLen]uint8
var dstMac1 [common.EtherAddrLen]uint8
var srcMac1 [common.EtherAddrLen]uint8
var modifyPacket = []func(pkt *packet.Packet, ctx flow.UserContext){modifyPacket0, modifyPacket1}
var direct = "direct"

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

func initCommonState() {
	// Parse arguments
	configFile := flag.String("config", "config.json", "Specify config file name")
	target := flag.String("target", "dcomp01", "Target host name from config file")
	flag.Parse()

	// Get source MAC addresses for port 0 and 1
	srcMac0 = flow.GetPortMACAddress(0)
	printMAC("Source MAC 0", srcMac0)
	srcMac1 = flow.GetPortMACAddress(1)
	printMAC("Source MAC 1", srcMac1)

	// Read config
	err := readConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	if *target == "" {
		target = &direct
	}

	// Get destination MAC addresses for port 0 and 1
	if hw, err := net.ParseMAC(config[*target][0]); err == nil {
		copy(dstMac0[:], hw)
	} else {
		log.Fatal(err)
	}
	printMAC("Destination MAC 0", dstMac0)
	if hw, err := net.ParseMAC(config[*target][1]); err == nil {
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
