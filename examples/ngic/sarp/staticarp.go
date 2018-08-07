//Package sarp ...
// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package sarp

import (
	"errors"
	"fmt"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"gopkg.in/ini.v1"
	"net"
	"os"
	"strings"
)

//lables
const (
	LblARPComplete   = "COMPLETED"
	LblARPInComplete = "INCOMPLETE"
	LblSectionS1U    = "s1u"
	LblSectionSGI    = "sgi"

	StaticARPFilePath = "config/static_arp.cfg"
)

var mapStaticArp map[uint32]ARPEntry

func init() {
	mapStaticArp = make(map[uint32]ARPEntry)
}

//ARPEntry ...
type ARPEntry struct {
	IP     net.IP
	MAC    net.HardwareAddr
	PORT   int
	STATUS string //int
}

//Configure ...
func Configure() {
	common.LogInfo(common.Info, " Populating Static ARP entries ...", StaticARPFilePath)
	cfg, err := ini.Load(StaticARPFilePath)
	flow.CheckFatal(err)

	for key, value := range cfg.Section(LblSectionS1U).KeysHash() {
		fmt.Println("[", LblSectionS1U, "]", key, value)
		AddArpData(key, value)
	}
	for key, value := range cfg.Section(LblSectionSGI).KeysHash() {
		fmt.Println("[", LblSectionSGI, "]", key, value)
		AddArpData(key, value)
	}
}

//AddArpData ...
func AddArpData(ipRange string, value string) {
	firstIP := net.ParseIP(strings.Split(ipRange, " ")[0])
	lastIP := net.ParseIP(strings.Split(ipRange, " ")[1])

	lowIP := common.Ip2int(firstIP)
	highIP := common.Ip2int(lastIP)

	if lowIP <= highIP {

		hw, err := net.ParseMAC(value)
		if err != nil {
			fmt.Errorf("Static ARP Config : Invalid MAC address %v ", value)
			os.Exit(1)
		} //
		for i := lowIP; i <= highIP; i++ {
			data := ARPEntry{
				IP:     common.Int2ip(i),
				STATUS: "COMPLETED",
				MAC:    hw,
			} //
			common.LogInfo(common.Info, "Entry : ", common.Int2ip(i), packet.StringToIPv4(data.IP.String()), packet.StringToIPv4(strings.Split(ipRange, " ")[0]))
			addStaticArpEntry(packet.StringToIPv4(common.Int2ip(i).String()), data)
		} //
	}
}

//Add static arp entry to ARP Table/Map
func addStaticArpEntry(ip uint32, data ARPEntry) {
	mapStaticArp[ip] = data
	common.LogInfo(common.Info, "Added Entry : ", ip, data)
}

//AddArpEntry ... Add arp entry to ARP table and queue the pkt
func AddArpEntry(ip uint32, pkt *packet.Packet) {
	arpEntry := ARPEntry{
		IP:     common.Int2ip(ip),
		STATUS: "INCOMPLETE",
	}
	mapStaticArp[ip] = arpEntry
	common.LogInfo(common.Info, "Added Entry : ", ip, arpEntry)
}

//LookArpTable Lookup arp table entry
func LookArpTable(ip uint32, pkt *packet.Packet) (net.HardwareAddr, error) {

	common.LogInfo(common.Info, "LookupARP ", ip)
	entry, ok := mapStaticArp[ip]
	if ok {
		if entry.STATUS == "COMPLETED" {
			return entry.MAC, nil
		}
		common.LogInfo(common.Info, "ARP is incomplete ", ip)
		return entry.MAC, errors.New("ARP is not resolved for IP ")
	}
	AddArpEntry(ip, pkt)
	common.LogInfo(common.Info, "ARP is not resolved for IP ", ip)
	return entry.MAC, errors.New("ARP is not resolved for IP ")
}
