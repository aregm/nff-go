// Copyright (c) 2003-2018, Great Software Laboratory Pvt. Ltd.
// Copyright (c) 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package arp

import (
	"container/ring"
	"errors"
	"fmt"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/ngic/utils"
	"github.com/intel-go/nff-go/packet"
	"gopkg.in/ini.v1"
	"net"
	"os"
	"strings"
	"time"
)

var map_static_arp map[uint32]ARP_ENTRY

func init() {
	map_static_arp = make(map[uint32]ARP_ENTRY)
}

//ARP Entry
type ARP_ENTRY struct {
	IP          net.IP
	MAC         [common.EtherAddrLen]uint8
	PORT        int
	STATUS      string //int
	LAST_UPDATE int64
	RING        *ring.Ring
}

//
// Method : Load the static arp entries from the config file and build the map
//
func ConfigureStaticArp(filepath string) {
	utils.LogInfo(utils.Info, " Populating Static ARP entries ...")
	cfg, err := ini.Load(filepath)
	utils.CheckFatal(err)

	for key, value := range cfg.Section(SECTION_S1U).KeysHash() {
		fmt.Println("[", SECTION_S1U, "]", key, value)
		AddArpData(key, value)
	}
	for key, value := range cfg.Section(SECTION_SGI).KeysHash() {
		fmt.Println("[", SECTION_SGI, "]", key, value)
		AddArpData(key, value)
	}
}

//
// Method :Add Arp Data
//
func AddArpData(ip_range string, value string) {
	first_ip := net.ParseIP(strings.Split(ip_range, " ")[0])
	last_ip := net.ParseIP(strings.Split(ip_range, " ")[1])

	low_ip := utils.Ip2int(first_ip)
	high_ip := utils.Ip2int(last_ip)

	if low_ip <= high_ip {

		var MacAddress [common.EtherAddrLen]uint8
		if hw, err := net.ParseMAC(value); err == nil {
			copy(MacAddress[:], hw)
		} else {
			fmt.Errorf("Static ARP Config : Invalid MAC address %v ", value)
			os.Exit(1)
		} //
		for i := low_ip; i <= high_ip; i++ {

			data := ARP_ENTRY{
				IP:          utils.Int2ip(i),
				STATUS:      "COMPLETED",
				MAC:         MacAddress,
				LAST_UPDATE: time.Now().UnixNano() / 1000000,
			} //
			utils.LogDebug(utils.Debug, "Entry : ", utils.Int2ip(i), utils.StringToIPv4(data.IP.String()), utils.StringToIPv4(strings.Split(ip_range, " ")[0]))
			addStaticArpEntry(utils.StringToIPv4(utils.Int2ip(i).String()), data)
		} //
	}
}

//
// Method : Add static arp entry to ARP Table/Map
//
func addStaticArpEntry(ip uint32, data ARP_ENTRY) {
	map_static_arp[ip] = data
	utils.LogDebug(utils.Debug, "Added Entry : ", ip, data)
	//	fmt.Println("Added Entry : ", ip, data)
}

//
// Method: Add arp entry to ARP table and queue the pkt
//
func AddArpEntry(ip uint32, pkt *packet.Packet) {

	arp_entry := ARP_ENTRY{
		IP:     utils.Int2ip(ip),
		STATUS: "INCOMPLETE",
		RING:   ring.New(4096),
	}
	arp_entry.RING.Value = pkt
	arp_entry.RING.Next()

	map_static_arp[ip] = arp_entry

	utils.LogDebug(utils.Debug, "Added Entry : ", ip, arp_entry)
	//	fmt.Println("Added Entry : ", ip, data)
}

//
//Method : Lookup arp table entry
//
func LookArpTable(ip uint32, pkt *packet.Packet) ([common.EtherAddrLen]uint8, error) {

	utils.LogDebug(utils.Debug, "LookupARP ", ip)

	entry, ok := map_static_arp[ip]
	if ok {
		if entry.STATUS == "COMPLETED" {
			return entry.MAC, nil
		} else {
			entry.RING.Value = pkt
			entry.RING.Next()
			utils.LogDebug(utils.Debug, "ARP is incomplete ", ip)
			return entry.MAC, errors.New("ARP is not resolved for IP ")
		}
	} else {
		AddArpEntry(ip, pkt)
		utils.LogDebug(utils.Debug, "ARP is not resolved for IP ", ip)
		return entry.MAC, errors.New("ARP is not resolved for IP ")
	}
}
