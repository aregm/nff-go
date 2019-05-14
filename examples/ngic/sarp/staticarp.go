//Package sarp ...
// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package sarp

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/ini.v1"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

//lables
const (
	LblARPComplete   = "COMPLETED"
	LblARPInComplete = "INCOMPLETE"
	LblSectionS1U    = "s1u"
	LblSectionSGI    = "sgi"

	StaticARPFilePath = "config/static_arp.cfg"
)

var mapStaticArp = map[types.IPv4Address]ARPEntry{}

//ARPEntry ...
type ARPEntry struct {
	IP       types.IPv4Address
	MAC      types.MACAddress
	COMPLETE bool
}

//Configure ...
func Configure() {
	common.LogDebug(common.Debug, " Populating Static ARP entries ...", StaticARPFilePath)
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
	addrs := strings.Split(ipRange, " ")
	lowIP, err := types.StringToIPv4(addrs[0])
	if err != nil {
		common.LogFatal(common.No, "Static ARP Config : Invalid IP address ", addrs[0])
	}
	highIP, err := types.StringToIPv4(addrs[1])
	if err != nil {
		common.LogFatal(common.No, "Static ARP Config : Invalid IP address ", addrs[1])
	}

	if lowIP <= highIP {
		hw, err := types.StringToMACAddress(value)
		if err != nil {
			common.LogFatal(common.No, "Static ARP Config : Invalid MAC address ", value)
		}
		common.LogDebug(common.No, "Filling up ARP entries from ", lowIP.String(), "to", highIP.String())
		for i := lowIP; i <= highIP; i++ {
			data := ARPEntry{
				IP:       i,
				MAC:      hw,
				COMPLETE: true,
			}
			common.LogDebug(common.Debug, "Entry from range : ", ipRange, ":", data)
			addStaticArpEntry(i, data)
		}
	}
}

//Add static arp entry to ARP Table/Map
func addStaticArpEntry(ip types.IPv4Address, data ARPEntry) {
	mapStaticArp[ip] = data
	common.LogDebug(common.Debug, "Added static Entry : ", ip.String(), data)
}

//AddArpEntry ... Add arp entry to ARP table and queue the pkt
func AddArpEntry(ip types.IPv4Address, pkt *packet.Packet) {
	arpEntry := ARPEntry{
		IP:       ip,
		COMPLETE: false,
	}
	mapStaticArp[ip] = arpEntry
	common.LogDebug(common.Debug, "Added ARP Entry : ", ip.String(), arpEntry)
}

//LookArpTable Lookup arp table entry
func LookArpTable(ip types.IPv4Address, pkt *packet.Packet) (types.MACAddress, error) {
	common.LogDebug(common.Debug, "LookupARP ", ip.String())
	entry, ok := mapStaticArp[ip]
	if ok {
		if entry.COMPLETE {
			return entry.MAC, nil
		}
		common.LogDebug(common.Debug, "ARP is incomplete ", ip.String())
		return entry.MAC, errors.New("ARP is not resolved for IP " + ip.String())
	}
	AddArpEntry(ip, pkt)
	common.LogDebug(common.Debug, "ARP is not resolved for IP ", ip.String())
	return entry.MAC, errors.New("ARP is not resolved for IP " + ip.String())
}
