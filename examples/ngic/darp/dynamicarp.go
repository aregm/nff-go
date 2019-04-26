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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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

const (
	//LblARPComplete lable arp complete
	LblARPComplete = "COMPLETED"
	//LblARPInComplete lable arp not complete
	LblARPInComplete = "INCOMPLETE"
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

	//var mapRouteTable map[uint32]netlink.Route
	mapRouteTable map[uint32]RouteEntry

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
	IP     net.IP
	IntIP  uint32
	MAC    net.HardwareAddr
	PORT   int
	STATUS string //int
}

//RouteEntry route entry with mac for the GW for lookup optimization
type RouteEntry struct {
	Dst *net.IPNet
	Gw  net.IP
	MAC net.HardwareAddr
}

//init ...
func init() {
	//mapRouteTable = make(map[uint32]netlink.Route)
	mapRouteTable = make(map[uint32]RouteEntry) //TODO optmized lookup for gw
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
		tmp := make(map[uint32]RouteEntry)
		fmt.Println("--------------------------------------")
		fmt.Println("Route Table")
		fmt.Println("--------------------------------------")
		for _, route := range routes {
			DstIP := uint32(types.StringToIPv4("0.0.0.0"))
			if route.Dst != nil {
				DstIP = uint32(types.StringToIPv4(route.Dst.IP.String()))
			}
			//common.LogDebug(common.Debug, "Adding Entry Dst# ", Int2ip(packet.SwapBytesUint32(DstIP)).String(), " , ", DstIP)
			//	tmp[DstIP] = route
			if route.Gw != nil {
				val, ok := dlMapArpTable.Load(types.StringToIPv4(route.Gw.String()))
				if ok {
					entry := val.(ARPEntry)
					_, routeExist := tmp[DstIP]
					if routeExist {
						if route.Priority > 0 {
							continue
						}
					}
					tmp[DstIP] = RouteEntry{Dst: route.Dst, Gw: route.Gw, MAC: entry.MAC}
				}
			} else {
				tmp[DstIP] = RouteEntry{Dst: route.Dst, Gw: route.Gw}
			}
			if route.Dst == nil {
				fmt.Printf("Route dst: NULL, route gateway: %+v\n", route.Gw)
			} else if route.Gw == nil {
				fmt.Printf("Route dst: %+v, route gateway: NULL\n", route.Dst)
			} else {
				fmt.Printf("Route dst: %+v, route gateway: %+v\n", route.Dst, route.Gw)
			}
		} //for
		fmt.Println("--------------------------------------")
		mapRouteTable = tmp
	} else {
		common.LogDebug(common.Debug, "Netlink : Unable to get route ", err)
	}
}

//GetRoute ...
func GetRoute(ip uint32) (RouteEntry, error) {
	common.LogDebug(common.Debug, " Get Route table entries ...")
	NETMASK := uint32(4294967040) //255.255.255.0 /24 TODO
	Dst := packet.SwapBytesUint32(ip) & NETMASK
	route, ok := mapRouteTable[packet.SwapBytesUint32(Dst)]

	if ok {
		common.LogDebug(common.Debug, "Found # Gw: ", route.Gw, ", ", route.Gw.String())
		return route, nil
	}
	return route, errors.New("Route not found")
} //

//lookupRoute using destip and return the gatway ip
func lookupRoute(ip uint32) (uint32, error) {
	common.LogDebug(common.Debug, " Lookup Route table entries ...")
	NETMASK := uint32(4294967040) //255.255.255.0 /24 TODO

	//common.LogDebug(common.Debug, "IP1: ", ip, " , ", packet.SwapBytesUint32(ip),Int2ip(packet.SwapBytesUint32(ip)).String())
	Dst := packet.SwapBytesUint32(ip) & NETMASK
	route, ok := mapRouteTable[packet.SwapBytesUint32(Dst)]

	if ok {
		//common.LogDebug(common.Debug, "Found # Gw: ", route.Gw, ", ", route.Gw.String())
		if route.Gw != nil {
			return uint32(types.StringToIPv4(route.Gw.String())), nil
		}
		return uint32(types.StringToIPv4("0.0.0.0")), nil
	}
	return uint32(types.StringToIPv4("0.0.0.0")), errors.New("Route not found")
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
			ipv4 := neigh.IP.To4()
			//	//common.LogDebug(common.Debug,"[DEBUG]",ip)
			if ipv4 != nil && !ipv4.IsLoopback() {
				common.LogDebug(common.Debug, "Adding Entry IP# ", ipv4.String(), " , ", types.StringToIPv4(ipv4.String()))
				fmt.Println(ipv4, " ", neigh.HardwareAddr)

				arpEntry := ARPEntry{
					MAC:    neigh.HardwareAddr,
					IP:     ipv4,
					STATUS: LblARPComplete,
				}

				ulMapArpTable.Store(types.StringToIPv4(ipv4.String()), arpEntry)
				dlMapArpTable.Store(types.StringToIPv4(ipv4.String()), arpEntry)

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
func updateLinuxArp(DeviceName string, ip net.IP, mac net.HardwareAddr) {
	common.LogDebug(common.Debug, "Updating linux arp entries", ip, mac)
	link, _ := netlink.LinkByName(DeviceName) //get SGI/S1U device name

	if link != nil {
		mutex.Lock()
		entry := netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			State:        netlink.NUD_PERMANENT,
			IP:           ip,
			HardwareAddr: mac,
		}
		err := netlink.NeighAdd(&entry)
		if err != nil {
			common.LogDebug(common.Debug, "Error creating linux arp entries", ip, mac)
			//	flow.CheckFatal(err)
		}
		mutex.Unlock()
	} else {
		common.LogDebug(common.Debug, "Error getting network link ")
	}

}

//Add arp incomplete entry to ARP table
func addDlArpEntry(ip uint32) ARPEntry {
	strIP := Int2ip(packet.SwapBytesUint32(ip))
	common.LogDebug(common.Debug, "[DL] AddULArp Entry  : ", strIP)
	arpEntry := ARPEntry{
		IP:     strIP,
		IntIP:  ip,
		STATUS: LblARPInComplete,
	}
	dlMapArpTable.Store(ip, arpEntry)
	return arpEntry
}

//Add arp incomplete entry to ARP table
func addUlArpEntry(ip uint32) ARPEntry {
	strIP := Int2ip(packet.SwapBytesUint32(ip))
	common.LogDebug(common.Debug, "[UL] AddULArp Entry  : ", strIP)
	arpEntry := ARPEntry{
		IP:     strIP,
		IntIP:  ip,
		STATUS: LblARPInComplete,
	}
	ulMapArpTable.Store(ip, arpEntry)
	return arpEntry
}

var onceULRebuildArpCache sync.Once
var onceDLRebuildArpCache sync.Once

//rebuild Arp cache from the route entry for GW
func rebuildDlArpCache(dstip uint32, mac net.HardwareAddr) {

	route, err := GetRoute(dstip)
	if err == nil {
		common.LogDebug(common.Debug, "[DL] RebuildArpCache : ", route.Dst)
		ipnet := route.Dst
		ip := route.Dst.IP
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); IncrementIP(ip) {
			arpEntry := ARPEntry{
				IP:     ip,
				STATUS: LblARPComplete,
				MAC:    mac,
			} //
			dlMapArpTable.Store(types.StringToIPv4(ip.String()), arpEntry)
			common.LogDebug(common.Debug, "[DL] Adding Arp Entry : ", ip, types.StringToIPv4(ip.String()))
		}
	}

}

//rebuild Arp cache from the route entry for GW
func rebuildUlArpCache(dstip uint32, mac net.HardwareAddr) {

	route, err := GetRoute(dstip)
	if err == nil {
		common.LogDebug(common.Debug, "[UL] RebuildArpCache : ", route.Dst.IP, route.Dst.Mask)
		ipnet := route.Dst
		ip := route.Dst.IP
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); IncrementIP(ip) {
			arpEntry := ARPEntry{
				IP:     ip,
				STATUS: LblARPComplete,
				MAC:    mac,
			} //
			ulMapArpTable.Store(types.StringToIPv4(ip.String()), arpEntry)
			common.LogDebug(common.Debug, "[UL] Adding Arp Entry : ", ip, types.StringToIPv4(ip.String()))
		}
	}

}

//LookupDlArpTable Lookup DL arp table using the ip
func LookupDlArpTable(ip uint32, pkt *packet.Packet) (net.HardwareAddr, bool, error) {
	//common.LogDebug(common.Debug, "[DL]LookupARP", ip)

	val, ok := dlMapArpTable.Load(ip)
	if ok {
		entry := val.(ARPEntry)
		if entry.STATUS == LblARPComplete {
			return entry.MAC, false, nil
		}
		putToDlQueue(entry, pkt)
		common.LogDebug(common.Debug, "[DL] ARP Incomplete  Queued Pkt ")
		return entry.MAC, false, errors.New("[DL] ARP is not resolved for IP ")
	}
	var entry = ARPEntry{}
	gw, err := lookupRoute(ip)
	if err == nil {
		//		common.LogDebug(common.Debug, "[DL]Found GW ", Int2ip(packet.SwapBytesUint32(gw)).String(), gw)
		if gw != 0 {
			val, ok = dlMapArpTable.Load(gw)
			common.LogDebug(common.Debug, "[DL] GW ARPEntry ", val, ok)
			if ok {
				entry = val.(ARPEntry)
				if entry.STATUS == LblARPComplete {
					onceDLRebuildArpCache.Do(func() { rebuildDlArpCache(ip, entry.MAC) })
					return entry.MAC, false, nil
				}
				putToDlQueue(entry, pkt)
				common.LogDebug(common.Debug, "[DL] GW ARP Incomplete Queued Pkt ")
				return entry.MAC, false, errors.New("[DL] ARP is not resolved for IP ")
			}
			ip = gw
		}
		entry := addDlArpEntry(ip)
		putToDlQueue(entry, pkt)
		common.LogDebug(common.Debug, "[DL] Adding ARP entry : Queued Pkt ", ip)
	}
	return entry.MAC, !ok, errors.New("[DL]ARP is not resolved for IP ")

}

//LookupUlArpTable lookup UL arp table
func LookupUlArpTable(ip uint32, pkt *packet.Packet) (net.HardwareAddr, bool, error) {

	//common.LogDebug(common.Debug, "[UL] LookupARP ", ip)
	val, ok := ulMapArpTable.Load(ip)
	if ok {
		entry := val.(ARPEntry)
		if entry.STATUS == LblARPComplete {
			return entry.MAC, false, nil
		}
		putToUlQueue(entry, pkt)
		common.LogDebug(common.Debug, "[UL] ARP is incomplete  Pkt added to Queue")
		return entry.MAC, false, errors.New("[UL] ARP is not resolved for IP ")
	}
	var entry = ARPEntry{}
	gw, err := lookupRoute(ip)
	if err == nil {
		//		common.LogDebug(common.Debug, "[UL] Found GW ", Int2ip(packet.SwapBytesUint32(gw)).String(), gw)
		if gw != 0 {
			val, ok = ulMapArpTable.Load(gw)
			common.LogDebug(common.Debug, "[UL] GW ARPEntry ", val, ok)
			if ok {
				entry := val.(ARPEntry)
				if entry.STATUS == LblARPComplete {
					onceULRebuildArpCache.Do(func() { rebuildUlArpCache(ip, entry.MAC) })
					return entry.MAC, false, nil
				}
				putToUlQueue(entry, pkt)
				common.LogDebug(common.Debug, "[UL] GW ARP is incomplete  Pkt added to Queue")
				return entry.MAC, false, errors.New("[UL] ARP is not resolved for IP ")
			}
			ip = gw
		}
		entry := addUlArpEntry(ip)
		putToUlQueue(entry, pkt)
		common.LogDebug(common.Debug, "[UL] Adding ARP entry :  Pkt added to Queue")
	}
	return entry.MAC, !ok, errors.New("[UL] ARP is not resolved for IP ")

}

// Clone the pkt and put into queue
func putToUlQueue(entry ARPEntry, srcPkt *packet.Packet) bool {
	clPkt, err := ClonePacket(srcPkt)
	if err == nil {
		val, ok := UlPktsQMap.Load(entry.IntIP)
		if !ok {
			val = queue.New(initSizePktsQueue)
			UlPktsQMap.Store(entry.IntIP, val)
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
		val, ok := DlPktsQMap.Load(entry.IntIP)
		if !ok {
			val = queue.New(initSizePktsQueue)
			DlPktsQMap.Store(entry.IntIP, val)
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

	spa := uint32(types.ArrayToIPv4(arpPkt.SPA))

	//common.LogDebug(common.Debug, "[DL]Update ARP ", Int2ip(packet.SwapBytesUint32(spa)), spa)

	val, ok := dlMapArpTable.Load(spa)
	if ok {
		entry := val.(ARPEntry)
		if entry.STATUS != LblARPComplete {
			mac, _ := net.ParseMAC(arpPkt.SHA.String())
			entry.MAC = mac
			entry.STATUS = LblARPComplete

			dlMapArpTable.Store(spa, entry)
			go sendDLQueuedPkts(entry, dstPort)
			updateLinuxArp(s1uDeviceName, entry.IP, entry.MAC)
			return true
		}

	} else {
		//common.LogDebug(common.Debug, "[DL]Unknown ARP Entry for  IP ", Int2ip(packet.SwapBytesUint32(spa)))
		//Adding ARP
		mac, err := net.ParseMAC(arpPkt.SHA.String())
		if err != nil {
			flow.CheckFatal(err)
		}
		arpEntry := ARPEntry{
			IP:     Int2ip(packet.SwapBytesUint32(spa)),
			MAC:    mac,
			STATUS: LblARPComplete,
		}
		dlMapArpTable.Store(spa, arpEntry)
	}

	return false
}

//UpdateUlArpTable : Update/Sync ARP cache on receipt of ARP response and send the queued pkts
func UpdateUlArpTable(arpPkt *packet.ARPHdr, dstPort uint16, sgiDeviceName string) bool {

	spa := uint32(types.ArrayToIPv4(arpPkt.SPA))

	//common.LogDebug(common.Debug, "[UL]Update ARP ", Int2ip(packet.SwapBytesUint32(spa)), spa)

	val, ok := ulMapArpTable.Load(spa)
	if ok {
		entry := val.(ARPEntry)
		if entry.STATUS != LblARPComplete {

			mac, _ := net.ParseMAC(arpPkt.SHA.String())
			entry.MAC = mac
			entry.STATUS = LblARPComplete
			ulMapArpTable.Store(spa, entry)
			//common.LogDebug(common.Debug, "[UL]  ARP  Entry COMPLETE ", spa, " , ", entry.MAC, ", ERROR =", " ,SHA =", arpPkt.SHA)
			go sendULQueuedPkts(entry, dstPort)
			updateLinuxArp(sgiDeviceName, entry.IP, entry.MAC)
			return true
		}

	} else {
		//common.LogDebug(common.Debug, "Unknown ARP Entry for  IP ", Int2ip(packet.SwapBytesUint32(spa)))
		//Adding ARP
		mac, err := net.ParseMAC(arpPkt.SHA.String())
		if err != nil {
			flow.CheckFatal(err)
		}
		arpEntry := ARPEntry{
			IP:     Int2ip(packet.SwapBytesUint32(spa)),
			MAC:    mac,
			STATUS: LblARPComplete,
		}
		ulMapArpTable.Store(spa, arpEntry)
	}
	return false

} //

//Send Queued pkt after ARP is resolved
func sendULQueuedPkts(entry ARPEntry, dstPort uint16) {
	if val, ok := UlPktsQMap.Load(entry.IntIP); ok {
		pktQueue := val.(*queue.Queue)

		items, err := pktQueue.Get(100)
		if err == nil {
			for _, item := range items {
				pkt := item.(*packet.Packet)
				copy(pkt.Ether.DAddr[:], entry.MAC)
				//common.LogDebug(common.Debug, "[UL] Sending queued pkts ", pkt)
				result := pkt.SendPacket(dstPort)
				if result == true {
					atomic.AddUint64(&UlTxCounter, 1)
					//common.LogDebug(common.Debug, "Sending success")
				} else {
					common.LogDebug(common.Debug, "Sending failed ")
				}
			}
		}
	}
}

//Send Queued pkt after ARP is resolved
func sendDLQueuedPkts(entry ARPEntry, dstPort uint16) {
	if val, ok := DlPktsQMap.Load(entry.IntIP); ok {
		pktQueue := val.(*queue.Queue)
		items, err := pktQueue.Get(100)
		if err == nil {
			for _, item := range items {
				pkt := item.(*packet.Packet)
				copy(pkt.Ether.DAddr[:], entry.MAC)
				//common.LogDebug(common.Debug, "[DL] Sending queued pkts ", pkt)
				result := pkt.SendPacket(dstPort)
				if result == true {
					atomic.AddUint64(&DlTxCounter, 1)
					//common.LogDebug(common.Debug, "Sending success")
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

// IncrementIP increments all bytes in IPv4 address.
func IncrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Int2ip converts int ip to net.IP.
func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
