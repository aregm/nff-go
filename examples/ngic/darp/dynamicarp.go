//Package darp ...
// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// Dynamic Arp support
//   It brings the linux ARP table and route table on fast path
// Flow:
//  If the mac for DestIP is not found
//  Then check route entry for it and then check the GW if it's 0 (means direct connection)
//  then prepare ARP request pkt and forward it.
//   if GW ip is not 0.0.0.0 (means switch exist inbetween)then check the arp table for gw entry
// most probably it will exist then update the next hop info and forward the pkt
//  else prepare ARP request pkt and forward it and queue the pkt (clone the pkt before adding to queue)
//  Once the arp response is received  ARP entry status changed to COMPLETE then iterate over queue
//  update the next hop info for each pkt  and  thenforward the pkts
//
package darp

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-collections/go-datastructures/queue"
	"github.com/vishvananda/netlink"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

// stats counters
var (
	UlTxCounter uint64
	DlTxCounter uint64
)

var (
	initSizePktsQueue = int64(10000)
)

var (
	mapRouteTable map[types.IPv4Address]RouteEntry

	ulMapArpTable sync.Map
	dlMapArpTable sync.Map

	//UlPktsQMap  Uplink queued pkt map
	UlPktsQMap sync.Map

	//DlPktsQMap Downlink queued pkt map
	DlPktsQMap sync.Map

	isRouteUpdated int32
)

//ARPEntry ...
type ARPEntry struct {
	IP       types.IPv4Address
	MAC      types.MACAddress
	PORT     int
	COMPLETE bool
}

//RouteEntry route entry with mac for the GW for lookup optimization
type RouteEntry struct {
	Dst *types.IPv4Subnet
	Gw  types.IPv4Address
	MAC types.MACAddress
}

//Configure initialize route,arp table add lister for any route modification and updat route table and arp entries a
func Configure() {
	initRouteTable()
	initArpTable()
	go checkIFRoutesUpdated()
	go subscribeToRouteEvents()
}

//Subscribes to route events
func subscribeToRouteEvents() {
	ch := make(chan netlink.RouteUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.RouteSubscribe(ch, done); err != nil {
		flow.CheckFatal(err)
	}
	expectRouteUpdate(ch)
}

//initiate route table
func initRouteTable() {
	common.LogDebug(common.Debug, " Populating Route table entries ...")

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err == nil {
		tmp := make(map[types.IPv4Address]RouteEntry)
		fmt.Println("--------------------------------------")
		fmt.Println("Route Table")
		fmt.Println("--------------------------------------")
		for _, route := range routes {
			var DstIP types.IPv4Address
			var routedst *types.IPv4Subnet
			if route.Dst != nil {
				routedst, err := types.NetIPNetToIPv4Subnet(route.Dst)
				flow.CheckFatal(err)
				DstIP = routedst.Addr
			}
			common.LogDebug(common.Debug, "Adding Entry for destination IP ", DstIP.String())
			if route.Gw != nil {
				gwip, err := types.NetIPToIPv4(route.Gw)
				flow.CheckFatal(err)
				val, ok := dlMapArpTable.Load(gwip)
				if ok {
					entry := val.(ARPEntry)
					_, routeExist := tmp[DstIP]
					if routeExist {
						if route.Priority > 0 {
							continue
						}
					}
					routegw, err := types.NetIPToIPv4(route.Gw)
					flow.CheckFatal(err)
					tmp[DstIP] = RouteEntry{
						Dst: routedst,
						Gw:  routegw,
						MAC: entry.MAC,
					}
				}
			} else {
				tmp[DstIP] = RouteEntry{Dst: routedst, Gw: 0}
			}
			if route.Dst == nil {
				fmt.Printf("Route dst: NULL, route gateway: %+v\n", route.Gw)
			} else if route.Gw == nil {
				fmt.Printf("Route dst: %+v, route gateway: NULL\n", route.Dst)
			} else {
				fmt.Printf("Route dst: %+v, route gateway: %+v\n", route.Dst, route.Gw)
			}
		}
		fmt.Println("--------------------------------------")
		mapRouteTable = tmp
	} else {
		common.LogError(common.Info, "Netlink : Unable to get route ", err)
	}
}

//GetRoute ...
func GetRoute(ip types.IPv4Address) (RouteEntry, error) {
	common.LogDebug(common.Debug, " Get Route table entries for IP ", ip.String())
	NETMASK := types.IPv4Address(0xffffff00) //255.255.255.0 /24 TODO
	Dst := packet.SwapBytesIPv4Addr(ip) & NETMASK
	route, ok := mapRouteTable[packet.SwapBytesIPv4Addr(Dst)]

	if ok {
		common.LogDebug(common.Debug, "Found # Gw: ", route.Gw.String())
		return route, nil
	}
	return route, errors.New("Route not found")
} //

//lookupRoute using destip and return the gatway ip
func lookupRoute(ip types.IPv4Address) (types.IPv4Address, error) {
	common.LogDebug(common.Debug, " Lookup Route table entries ...")
	NETMASK := types.IPv4Address(0xffffff00) //255.255.255.0 /24 TODO

	common.LogDebug(common.Debug, "IP1: ", ip.String())
	Dst := packet.SwapBytesIPv4Addr(ip) & NETMASK
	route, ok := mapRouteTable[packet.SwapBytesIPv4Addr(Dst)]

	if ok {
		common.LogDebug(common.Debug, "Found # Gw: ", route.Gw.String())
		return route.Gw, nil
	}
	return 0, errors.New("Route not found")
} //

// initialize the arp table using netlink call
func initArpTable() {
	common.LogDebug(common.Debug, " Populating ARP cache entries ...")
	// Dump and see that all added entries are there
	dump, err := netlink.NeighList(0, 0)
	if err == nil {
		fmt.Println("--------------------------------------")
		fmt.Println("ARP Table")
		fmt.Println("--------------------------------------")
		for _, neigh := range dump {
			if neigh.IP.To4() == nil {
				// Skip IPv6 routes for now
				continue
			}
			ipv4, err := types.NetIPToIPv4(neigh.IP)
			flow.CheckFatal(err)
			if ipv4 != 0 && !neigh.IP.IsLoopback() {
				common.LogDebug(common.Debug, "Adding Entry IP# ", ipv4.String())
				fmt.Println(ipv4, " ", neigh.HardwareAddr)

				arpEntry := ARPEntry{
					IP:       ipv4,
					MAC:      types.NetHWAddressToMAC(neigh.HardwareAddr),
					COMPLETE: true,
				}

				ulMapArpTable.Store(ipv4, arpEntry)
				dlMapArpTable.Store(ipv4, arpEntry)
			}
		}
		fmt.Println("--------------------------------------")
	} else {
		common.LogDebug(common.Debug, "Netlink : Unable to get arp table entries ", err)
	}
}

// poll for the route update events
func expectRouteUpdate(ch <-chan netlink.RouteUpdate) {
	for {
		time.After(time.Second)
		select {
		case update := <-ch:
			if update.Type == uint16(24) {
				//common.LogDebug(common.Debug, " Route added : ", update.Route)
				atomic.StoreInt32(&isRouteUpdated, int32(1))
			}
			if update.Type == uint16(25) {
				//common.LogDebug(common.Debug, " Route deleted :", update.Route)
				atomic.StoreInt32(&isRouteUpdated, int32(1))
			}
		}
	}
}

//check if the routes needs to be updated
func checkIFRoutesUpdated() {
	for {
		time.Sleep(time.Second * 2)
		if atomic.LoadInt32(&isRouteUpdated) != 0 {
			common.LogDebug(common.Debug, " Updating Refreshing table/Arp entries ...")
			fmt.Println(" Updating Refreshing table/Arp entries ...")
			initRouteTable()
			initArpTable()
			time.Sleep(time.Second * 1)
			atomic.StoreInt32(&isRouteUpdated, int32(0))
		}
	} //
}

var mutex sync.Mutex

//Updating linux arp entries
func updateLinuxArp(DeviceName string, ip types.IPv4Address, mac types.MACAddress) {
	common.LogDebug(common.Debug, "Updating linux arp entries", ip, mac)
	link, err := netlink.LinkByName(DeviceName) //get SGI/S1U device name
	flow.CheckFatal(err)

	if link != nil {
		mutex.Lock()
		entry := netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			State:        netlink.NUD_PERMANENT,
			IP:           types.IPv4ToNetIP(ip),
			HardwareAddr: types.MACAddressToNetHW(mac),
		}
		err := netlink.NeighAdd(&entry)
		if err != nil {
			common.LogDebug(common.Debug, "Error creating linux arp entries", ip, mac)
			flow.CheckFatal(err)
		}
		mutex.Unlock()
	} else {
		common.LogDebug(common.Debug, "Error getting network link ")
	}

}

//Add arp incomplete entry to ARP table
func addDlArpEntry(ip types.IPv4Address) ARPEntry {
	common.LogDebug(common.Debug, "[DL] AddULArp Entry  : ", ip.String())
	arpEntry := ARPEntry{
		IP:       ip,
		COMPLETE: false,
	}
	dlMapArpTable.Store(ip, arpEntry)
	return arpEntry
}

//Add arp incomplete entry to ARP table
func addUlArpEntry(ip types.IPv4Address) ARPEntry {
	common.LogDebug(common.Debug, "[UL] AddULArp Entry  : ", ip.String())
	arpEntry := ARPEntry{
		IP:       ip,
		COMPLETE: false,
	}
	ulMapArpTable.Store(ip, arpEntry)
	return arpEntry
}

var onceULRebuildArpCache sync.Once
var onceDLRebuildArpCache sync.Once

//rebuild Arp cache from the route entry for GW
func rebuildDlArpCache(dstip types.IPv4Address, mac types.MACAddress) {
	route, err := GetRoute(dstip)
	if err == nil {
		common.LogDebug(common.Debug, "[DL] RebuildArpCache : ", route.Dst.String())
		ipnet := route.Dst
		for ip := ipnet.Addr; ipnet.CheckIPv4AddressWithinSubnet(ip); ip++ {
			arpEntry := ARPEntry{
				IP:       ip,
				MAC:      mac,
				COMPLETE: true,
			}
			dlMapArpTable.Store(ip, arpEntry)
			common.LogDebug(common.Debug, "[DL] Adding Arp Entry : ", ip.String())
		}
	}
}

//rebuild Arp cache from the route entry for GW
func rebuildUlArpCache(dstip types.IPv4Address, mac types.MACAddress) {
	route, err := GetRoute(dstip)
	if err == nil {
		common.LogDebug(common.Debug, "[UL] RebuildArpCache : ", route.Dst.String())
		ipnet := route.Dst
		for ip := ipnet.Addr; ipnet.CheckIPv4AddressWithinSubnet(ip); ip++ {
			arpEntry := ARPEntry{
				IP:       ip,
				MAC:      mac,
				COMPLETE: true,
			}
			ulMapArpTable.Store(ip, arpEntry)
			common.LogDebug(common.Debug, "[UL] Adding Arp Entry : ", ip.String())
		}
	}
}

//LookupDlArpTable Lookup DL arp table using the ip
func LookupDlArpTable(ip types.IPv4Address, pkt *packet.Packet) (types.MACAddress, bool, error) {
	common.LogDebug(common.Debug, "[DL]LookupARP", ip)
	val, ok := dlMapArpTable.Load(ip)
	if ok {
		entry := val.(ARPEntry)
		if entry.COMPLETE {
			return entry.MAC, false, nil
		}
		putToDlQueue(entry, pkt)
		common.LogDebug(common.Debug, "[DL] ARP Incomplete  Queued Pkt ")
		return entry.MAC, false, fmt.Errorf("[DL] ARP is not resolved for IP %v", ip)
	}
	var entry = ARPEntry{}
	gw, err := lookupRoute(ip)
	if err == nil {
		common.LogDebug(common.Debug, "[DL]Found GW ", gw.String())
		if gw != 0 {
			val, ok = dlMapArpTable.Load(gw)
			common.LogDebug(common.Debug, "[DL] GW ARPEntry ", val, ok)
			if ok {
				entry = val.(ARPEntry)
				if entry.COMPLETE {
					onceDLRebuildArpCache.Do(func() { rebuildDlArpCache(ip, entry.MAC) })
					return entry.MAC, false, nil
				}
				putToDlQueue(entry, pkt)
				common.LogDebug(common.Debug, "[DL] GW ARP Incomplete Queued Pkt ")
				return entry.MAC, false, fmt.Errorf("[DL] ARP is not resolved for IP %v", ip)
			}
			ip = gw
		}
		entry := addDlArpEntry(ip)
		putToDlQueue(entry, pkt)
		common.LogDebug(common.Debug, "[DL] Adding ARP entry : Queued Pkt ", ip)
	}
	return entry.MAC, !ok, fmt.Errorf("[DL]ARP is not resolved for IP %v", ip)

}

//LookupUlArpTable lookup UL arp table
func LookupUlArpTable(ip types.IPv4Address, pkt *packet.Packet) (types.MACAddress, bool, error) {
	common.LogDebug(common.Debug, "[UL] LookupARP ", ip)
	val, ok := ulMapArpTable.Load(ip)
	if ok {
		entry := val.(ARPEntry)
		if entry.COMPLETE {
			return entry.MAC, false, nil
		}
		putToUlQueue(entry, pkt)
		common.LogDebug(common.Debug, "[UL] ARP is incomplete  Pkt added to Queue")
		return entry.MAC, false, fmt.Errorf("[UL] ARP is not resolved for IP %v", ip)
	}
	var entry = ARPEntry{}
	gw, err := lookupRoute(ip)
	if err == nil {
		common.LogDebug(common.Debug, "[UL] Found GW ", gw.String())
		if gw != 0 {
			val, ok = ulMapArpTable.Load(gw)
			common.LogDebug(common.Debug, "[UL] GW ARPEntry ", val, ok)
			if ok {
				entry := val.(ARPEntry)
				if entry.COMPLETE {
					onceULRebuildArpCache.Do(func() { rebuildUlArpCache(ip, entry.MAC) })
					return entry.MAC, false, nil
				}
				putToUlQueue(entry, pkt)
				common.LogDebug(common.Debug, "[UL] GW ARP is incomplete Pkt added to Queue")
				return entry.MAC, false, fmt.Errorf("[UL] ARP is not resolved for IP %v", ip)
			}
			ip = gw
		}
		entry := addUlArpEntry(ip)
		putToUlQueue(entry, pkt)
		common.LogDebug(common.Debug, "[UL] Adding ARP entry :  Pkt added to Queue")
	}
	return entry.MAC, !ok, fmt.Errorf("[UL] ARP is not resolved for IP %v", ip)
}

// Clone the pkt and put into queue
func putToUlQueue(entry ARPEntry, srcPkt *packet.Packet) bool {
	clPkt, err := ClonePacket(srcPkt)
	if err == nil {
		val, ok := UlPktsQMap.Load(entry.IP)
		if !ok {
			val = queue.New(initSizePktsQueue)
			UlPktsQMap.Store(entry.IP, val)
		}
		pktQueue := val.(*queue.Queue)
		pktQueue.Put(clPkt)
		return true
	}
	common.LogDebug(common.Debug, "[UL] ERROR while cloning pkt ", clPkt)
	return false
}

// Clone the pkt and put into queue
func putToDlQueue(entry ARPEntry, srcPkt *packet.Packet) bool {
	clPkt, err := ClonePacket(srcPkt)
	if err == nil {
		val, ok := DlPktsQMap.Load(entry.IP)
		if !ok {
			val = queue.New(initSizePktsQueue)
			DlPktsQMap.Store(entry.IP, val)
		}
		pktQueue := val.(*queue.Queue)
		pktQueue.Put(clPkt)
		return true
	}
	common.LogDebug(common.Debug, "[DL] ERROR while cloning pkt ", clPkt)
	return false

}

//UpdateDlArpTable ...
//Update/Sync ARP cache on receipt of ARP response and send the queued pkts
func UpdateDlArpTable(arpPkt *packet.ARPHdr, dstPort uint16, s1uDeviceName string) bool {
	spa := types.ArrayToIPv4(arpPkt.SPA)

	common.LogDebug(common.Debug, "[DL]Update ARP ", spa.String())

	val, ok := dlMapArpTable.Load(spa)
	if ok {
		entry := val.(ARPEntry)
		if !entry.COMPLETE {
			entry.MAC = arpPkt.SHA
			entry.COMPLETE = true

			dlMapArpTable.Store(spa, entry)
			go sendDLQueuedPkts(entry, dstPort)
			updateLinuxArp(s1uDeviceName, entry.IP, entry.MAC)
			return true
		}

	} else {
		common.LogDebug(common.Debug, "[DL]Unknown ARP Entry for IP ", spa.String())
		//Adding ARP
		arpEntry := ARPEntry{
			IP:       spa,
			MAC:      arpPkt.SHA,
			COMPLETE: true,
		}
		dlMapArpTable.Store(spa, arpEntry)
	}

	return false
}

//UpdateUlArpTable : Update/Sync ARP cache on receipt of ARP response and send the queued pkts
func UpdateUlArpTable(arpPkt *packet.ARPHdr, dstPort uint16, sgiDeviceName string) bool {
	spa := types.ArrayToIPv4(arpPkt.SPA)

	common.LogDebug(common.Debug, "[UL]Update ARP ", spa.String())

	val, ok := ulMapArpTable.Load(spa)
	if ok {
		entry := val.(ARPEntry)
		if !entry.COMPLETE {
			entry.MAC = arpPkt.SHA
			entry.COMPLETE = true

			ulMapArpTable.Store(spa, entry)
			go sendULQueuedPkts(entry, dstPort)
			updateLinuxArp(sgiDeviceName, entry.IP, entry.MAC)
			return true
		}

	} else {
		common.LogDebug(common.Debug, "Unknown ARP Entry for IP ", spa.String())
		//Adding ARP
		arpEntry := ARPEntry{
			IP:       spa,
			MAC:      arpPkt.SHA,
			COMPLETE: true,
		}
		ulMapArpTable.Store(spa, arpEntry)
	}
	return false

} //

//Send Queued pkt after ARP is resolved
func sendULQueuedPkts(entry ARPEntry, dstPort uint16) {
	if val, ok := UlPktsQMap.Load(entry.IP); ok {
		pktQueue := val.(*queue.Queue)

		items, err := pktQueue.Get(100)
		if err == nil {
			for _, item := range items {
				pkt := item.(*packet.Packet)
				pkt.Ether.DAddr = entry.MAC
				common.LogDebug(common.Debug, "[UL] Sending queued pkts ", pkt)
				result := pkt.SendPacket(dstPort)
				if result == true {
					atomic.AddUint64(&UlTxCounter, 1)
					common.LogDebug(common.Debug, "Sending success")
				} else {
					common.LogDebug(common.Debug, "Sending failed ")
				}
			}
		}
	}
}

//Send Queued pkt after ARP is resolved
func sendDLQueuedPkts(entry ARPEntry, dstPort uint16) {
	if val, ok := DlPktsQMap.Load(entry.IP); ok {
		pktQueue := val.(*queue.Queue)
		items, err := pktQueue.Get(100)
		if err == nil {
			for _, item := range items {
				pkt := item.(*packet.Packet)
				pkt.Ether.DAddr = entry.MAC
				common.LogDebug(common.Debug, "[DL] Sending queued pkts ", pkt)
				result := pkt.SendPacket(dstPort)
				if result == true {
					atomic.AddUint64(&DlTxCounter, 1)
					common.LogDebug(common.Debug, "Sending success")
				} else {
					common.LogDebug(common.Debug, "Sending failed ")
				}
			}
		}
	}
}

//ClonePacket clone existing packet
func ClonePacket(srcPkt *packet.Packet) (*packet.Packet, error) {

	clonePkt, err := packet.NewPacket()
	if err != nil {
		return clonePkt, err
	}
	//InitEmptyIPv4UDPPacket(pkt, packet.GetPacketLen())
	if packet.GeneratePacketFromByte(clonePkt, srcPkt.GetRawPacketBytes()) {
		return clonePkt, nil
	}
	return clonePkt, errors.New("Unable to clone pkt ")
}
