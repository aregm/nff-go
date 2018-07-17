//Package darp ...
// Copyright (c) 2017 Intel Corporation.
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
	"github.com/golang-collections/go-datastructures/queue"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/examples/ngic/global"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/vishvananda/netlink"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	//LblARPComplete lable arp complete
	LblARPComplete = "COMPLETED"
	//LblARPInComplete lable arp not complete
	LblARPInComplete = "INCOMPLETE"
)

var mapRouteTable map[uint32]netlink.Route

var ulMapArpTable sync.Map
var dlMapArpTable sync.Map

var ulPktsQueue = queue.New(10000)
var dlPktsQueue = queue.New(10000)

var isRouteUpdated int32

//ARPEntry ...
type ARPEntry struct {
	IP     net.IP
	MAC    net.HardwareAddr
	PORT   int
	STATUS string //int
}

//init ...
func init() {
	mapRouteTable = make(map[uint32]netlink.Route)
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
	common.LogInfo(common.Info, " Populating Route table entries ...")

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err == nil {

		tmp := make(map[uint32]netlink.Route)
		fmt.Println("--------------------------------------")
		fmt.Println("Route Table")
		fmt.Println("--------------------------------------")
		for _, route := range routes {
			DstIP := common.StringToIPv4("0.0.0.0")
			if route.Dst != nil {
				DstIP = common.StringToIPv4(route.Dst.IP.String())
			}
			//common.LogInfo(common.Info, "Adding Entry Dst# ", common.Int2ip(packet.SwapBytesUint32(DstIP)).String(), " , ", DstIP)
			fmt.Println(route.Dst, " ", route.Gw)
			tmp[DstIP] = route
		} //for
		fmt.Println("--------------------------------------")
		mapRouteTable = tmp
	} else {
		common.LogInfo(common.Info, "Netlink : Unable to get route ", err)
	}
}

//GetRoute ...
func GetRoute(ip uint32) (netlink.Route, error) {
	common.LogInfo(common.Info, " Get Route table entries ...")
	NETMASK := uint32(4294967040) //255.255.255.0 /24 TODO
	Dst := packet.SwapBytesUint32(ip) & NETMASK
	route, ok := mapRouteTable[packet.SwapBytesUint32(Dst)]

	if ok {
		common.LogInfo(common.Info, "Found # Gw: ", route.Gw, ", ", route.Gw.String())
		return route, nil
	}
	return route, errors.New("Route not found")
} //

//lookupRoute using destip and return the gatway ip
func lookupRoute(ip uint32) (uint32, error) {
	common.LogInfo(common.Info, " Lookup Route table entries ...")
	NETMASK := uint32(4294967040) //255.255.255.0 /24 TODO

	//common.LogInfo(common.Info, "IP1: ", ip, " , ", packet.SwapBytesUint32(ip),common.Int2ip(packet.SwapBytesUint32(ip)).String())
	Dst := packet.SwapBytesUint32(ip) & NETMASK
	route, ok := mapRouteTable[packet.SwapBytesUint32(Dst)]

	if ok {
		//common.LogInfo(common.Info, "Found # Gw: ", route.Gw, ", ", route.Gw.String())
		if route.Gw != nil {
			return common.StringToIPv4(route.Gw.String()), nil
		}
		return common.StringToIPv4("0.0.0.0"), nil
	}
	return common.StringToIPv4("0.0.0.0"), errors.New("Route not found")
} //

// initialize the arp table using netlink call
func initArpTable() {
	common.LogInfo(common.Info, " Populating ARP cache entries ...")
	// Dump and see that all added entries are there
	dump, err := netlink.NeighList(0, 0)
	if err == nil {
		fmt.Println("--------------------------------------")
		fmt.Println("ARP Table")
		fmt.Println("--------------------------------------")
		for _, neigh := range dump {
			ipv4 := neigh.IP.To4()
			//	//common.LogInfo(common.Info,"[DEBUG]",ip)
			if ipv4 != nil && !ipv4.IsLoopback() {
				common.LogInfo(common.Info, "Adding Entry IP# ", ipv4.String(), " , ", common.StringToIPv4(ipv4.String()))
				fmt.Println(ipv4, " ", neigh.HardwareAddr)

				arpEntry := ARPEntry{
					MAC:    neigh.HardwareAddr,
					IP:     ipv4,
					STATUS: LblARPComplete,
				}

				ulMapArpTable.Store(common.StringToIPv4(ipv4.String()), arpEntry)
				dlMapArpTable.Store(common.StringToIPv4(ipv4.String()), arpEntry)

			}
		}
		fmt.Println("--------------------------------------")
	} else {
		common.LogInfo(common.Info, "Netlink : Unable to get arp table entries ", err)
	}
}

// poll for the route update events
func expectRouteUpdate(ch <-chan netlink.RouteUpdate) {
	for {
		time.After(time.Second)
		select {
		case update := <-ch:
			if update.Type == uint16(24) {
				//common.LogInfo(common.Info, " Route added : ", update.Route)
				atomic.StoreInt32(&isRouteUpdated, int32(1))
			}
			if update.Type == uint16(25) {
				//common.LogInfo(common.Info, " Route deleted :", update.Route)
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
			common.LogInfo(common.Info, " Updating Refreshing table/Arp entries ...")
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
	common.LogInfo(common.Info, "Updating linux arp entries", ip, mac)
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
			common.LogInfo(common.Info, "Error creating linux arp entries", ip, mac)
			//	flow.CheckFatal(err)
		}
		mutex.Unlock()
	} else {
		common.LogInfo(common.Info, "Error getting network link ")
	}

}

//Add arp incomplete entry to ARP table
func addDlArpEntry(ip uint32) {
	arpEntry := ARPEntry{
		IP:     common.Int2ip(packet.SwapBytesUint32(ip)),
		STATUS: LblARPInComplete,
	}
	dlMapArpTable.Store(ip, arpEntry)
}

//Add arp incomplete entry to ARP table
func addUlArpEntry(ip uint32) {
	arpEntry := ARPEntry{
		IP:     common.Int2ip(packet.SwapBytesUint32(ip)),
		STATUS: LblARPInComplete,
	}
	ulMapArpTable.Store(ip, arpEntry)
}

var onceULRebuildArpCache sync.Once
var onceDLRebuildArpCache sync.Once

//rebuild Arp cache from the route entry for GW
func rebuildDlArpCache(dstip uint32, mac net.HardwareAddr) {

	route, err := GetRoute(dstip)
	if err == nil {
		common.LogInfo(common.Info, "[DL] RebuildArpCache : ", route.Dst.IP, route.Dst.Mask)
		ipnet := route.Dst
		ip := route.Dst.IP
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); common.IncrementIP(ip) {
			arpEntry := ARPEntry{
				IP:     ip,
				STATUS: LblARPComplete,
				MAC:    mac,
			} //
			dlMapArpTable.Store(common.StringToIPv4(ip.String()), arpEntry)
			common.LogInfo(common.Info, "[DL] Adding Arp Entry : ", ip, common.StringToIPv4(ip.String()))
		}
	}

}

//rebuild Arp cache from the route entry for GW
func rebuildUlArpCache(dstip uint32, mac net.HardwareAddr) {

	route, err := GetRoute(dstip)
	if err == nil {
		common.LogInfo(common.Info, "[UL] RebuildArpCache : ", route.Dst.IP, route.Dst.Mask)
		ipnet := route.Dst
		ip := route.Dst.IP
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); common.IncrementIP(ip) {
			arpEntry := ARPEntry{
				IP:     ip,
				STATUS: LblARPComplete,
				MAC:    mac,
			} //
			ulMapArpTable.Store(common.StringToIPv4(ip.String()), arpEntry)
			common.LogInfo(common.Info, "[UL] Adding Arp Entry : ", ip, common.StringToIPv4(ip.String()))
		}
	}

}

//LookupDlArpTable Lookup DL arp table using the ip
func LookupDlArpTable(ip uint32, pkt *packet.Packet) (net.HardwareAddr, bool, error) {
	//common.LogInfo(common.Info, "[DL]LookupARP", ip)

	val, ok := dlMapArpTable.Load(ip)
	if ok {
		entry := val.(ARPEntry)
		if entry.STATUS == LblARPComplete {
			return entry.MAC, false, nil
		}
		putToDlQueue(pkt)
		common.LogInfo(common.Info, "[DL] ARP Incomplete  Queued Pkt ", dlPktsQueue.Len())
		return entry.MAC, false, errors.New("[DL] ARP is not resolved for IP ")
	}
	var entry = ARPEntry{}
	gw, err := lookupRoute(ip)
	if err == nil {
		common.LogInfo(common.Info, "[DL]Found GW ", common.Int2ip(packet.SwapBytesUint32(gw)).String(), gw)
		if gw != 0 {
			val, ok = dlMapArpTable.Load(gw)
			common.LogInfo(common.Info, "[DL] GW ARPEntry ", val, ok)
			if ok {
				entry = val.(ARPEntry)
				if entry.STATUS == LblARPComplete {
					onceDLRebuildArpCache.Do(func() { rebuildDlArpCache(ip, entry.MAC) })
					return entry.MAC, false, nil
				}
				putToDlQueue(pkt)
				common.LogInfo(common.Info, "[DL] GW ARP Incomplete Queued Pkt ", dlPktsQueue.Len())
				return entry.MAC, false, errors.New("[DL] ARP is not resolved for IP ")
			}
			ip = gw
		}
		addDlArpEntry(ip)
		putToDlQueue(pkt)
		common.LogInfo(common.Info, "[DL] Adding ARP entry : Queued Pkt ", ip, dlPktsQueue.Len())
	}
	return entry.MAC, !ok, errors.New("[DL]ARP is not resolved for IP ")

}

//LookupUlArpTable lookup UL arp table
func LookupUlArpTable(ip uint32, pkt *packet.Packet) (net.HardwareAddr, bool, error) {

	//common.LogInfo(common.Info, "[UL] LookupARP ", ip)
	val, ok := ulMapArpTable.Load(ip)
	if ok {
		entry := val.(ARPEntry)
		if entry.STATUS == LblARPComplete {
			return entry.MAC, false, nil
		}
		putToUlQueue(pkt)
		common.LogInfo(common.Info, "[UL] ARP is incomplete  Pkt added to Queue", ulPktsQueue.Len())
		return entry.MAC, false, errors.New("[UL] ARP is not resolved for IP ")
	}
	var entry = ARPEntry{}
	gw, err := lookupRoute(ip)
	if err == nil {
		common.LogInfo(common.Info, "[UL] Found GW ", common.Int2ip(packet.SwapBytesUint32(gw)).String(), gw)
		if gw != 0 {
			val, ok = ulMapArpTable.Load(gw)
			common.LogInfo(common.Info, "[UL] GW ARPEntry ", val, ok)
			if ok {
				entry := val.(ARPEntry)
				if entry.STATUS == LblARPComplete {
					onceULRebuildArpCache.Do(func() { rebuildUlArpCache(ip, entry.MAC) })
					return entry.MAC, false, nil
				}
				putToUlQueue(pkt)
				common.LogInfo(common.Info, "[UL] GW ARP is incomplete  Pkt added to Queue", ulPktsQueue.Len())
				return entry.MAC, false, errors.New("[UL] ARP is not resolved for IP ")
			}
			ip = gw
		}
		addUlArpEntry(ip)
		putToUlQueue(pkt)
		common.LogInfo(common.Info, "[UL] Adding ARP entry :  Pkt added to Queue", ulPktsQueue.Len())
	}
	return entry.MAC, !ok, errors.New("[UL] ARP is not resolved for IP ")

}

// Clone the pkt and put into queue
func putToUlQueue(srcPkt *packet.Packet) bool {
	clPkt, err := ClonePacket(srcPkt)
	if err == nil {
		ulPktsQueue.Put(clPkt)
		return true
	}
	common.LogInfo(common.Info, "[UL] ERROR while cloning pkt ", clPkt)
	return false
}

// Clone the pkt and put into queue
func putToDlQueue(srcPkt *packet.Packet) bool {
	clPkt, err := ClonePacket(srcPkt)
	if err == nil {
		dlPktsQueue.Put(clPkt)
		return true
	}
	common.LogInfo(common.Info, "[DL] ERROR while cloning pkt ", clPkt)
	return false

}

//UpdateDlArpTable ...
//Update/Sync ARP cache on receipt of ARP response and send the queued pkts
func UpdateDlArpTable(arpPkt *packet.ARPHdr, dstPort uint16, s1uDeviceName string) bool {

	spa := common.ByteAryToIPv4(arpPkt.SPA)

	//common.LogInfo(common.Info, "[DL]Update ARP ", common.Int2ip(packet.SwapBytesUint32(spa)), spa)

	val, ok := dlMapArpTable.Load(spa)
	if ok {
		entry := val.(ARPEntry)
		if entry.STATUS != LblARPComplete {
			mac, _ := net.ParseMAC(packet.MACToString(arpPkt.SHA))
			entry.MAC = mac
			entry.STATUS = LblARPComplete

			dlMapArpTable.Store(spa, entry)
			sendDLQueuedPkts(entry, dstPort)
			updateLinuxArp(s1uDeviceName, entry.IP, entry.MAC)
			return true
		}

	} else {
		//common.LogInfo(common.Info, "[DL]Unknown ARP Entry for  IP ", common.Int2ip(packet.SwapBytesUint32(spa)))
		//Adding ARP
		mac, err := net.ParseMAC(packet.MACToString(arpPkt.SHA))
		if err != nil {
			flow.CheckFatal(err)
		}
		arpEntry := ARPEntry{
			IP:     common.Int2ip(packet.SwapBytesUint32(spa)),
			MAC:    mac,
			STATUS: LblARPComplete,
		}
		dlMapArpTable.Store(spa, arpEntry)
	}

	return false
}

//UpdateUlArpTable : Update/Sync ARP cache on receipt of ARP response and send the queued pkts
func UpdateUlArpTable(arpPkt *packet.ARPHdr, dstPort uint16, sgiDeviceName string) bool {

	spa := common.ByteAryToIPv4(arpPkt.SPA)

	//common.LogInfo(common.Info, "[UL]Update ARP ", common.Int2ip(packet.SwapBytesUint32(spa)), spa)

	val, ok := ulMapArpTable.Load(spa)
	if ok {
		entry := val.(ARPEntry)
		if entry.STATUS != LblARPComplete {

			mac, _ := net.ParseMAC(packet.MACToString(arpPkt.SHA))
			entry.MAC = mac
			entry.STATUS = LblARPComplete
			ulMapArpTable.Store(spa, entry)
			//common.LogInfo(common.Info, "[UL]  ARP  Entry COMPLETE ", spa, " , ", entry.MAC, ", ERROR =", " ,SHA =", arpPkt.SHA)
			sendULQueuedPkts(entry, dstPort)
			updateLinuxArp(sgiDeviceName, entry.IP, entry.MAC)
			return true
		}

	} else {
		//common.LogInfo(common.Info, "Unknown ARP Entry for  IP ", common.Int2ip(packet.SwapBytesUint32(spa)))
		//Adding ARP
		mac, err := net.ParseMAC(packet.MACToString(arpPkt.SHA))
		if err != nil {
			flow.CheckFatal(err)
		}
		arpEntry := ARPEntry{
			IP:     common.Int2ip(packet.SwapBytesUint32(spa)),
			MAC:    mac,
			STATUS: LblARPComplete,
		}
		ulMapArpTable.Store(spa, arpEntry)
	}
	return false

} //

//Send Queued pkt after ARP is resolved
func sendULQueuedPkts(entry ARPEntry, dstPort uint16) {
	for {
		items, err := ulPktsQueue.Get(10)
		if err == nil {
			for _, item := range items {
				pkt := item.(*packet.Packet)
				copy(pkt.Ether.DAddr[:], entry.MAC)
				//common.LogInfo(common.Info, "[UL] Sending queued pkts ", pkt)
				result := pkt.SendPacket(dstPort)
				if result == true {
					atomic.AddUint64(&global.UlTxCounter, 1)
					//common.LogInfo(common.Info, "Sending success")
				} else {
					common.LogInfo(common.Info, "Sending failed ")
				}
			}
		}
		if ulPktsQueue.Len() == 0 {
			break
		}
	}

	common.LogInfo(common.Info, "[UL] Sending queued pkts ", ulPktsQueue.Len())
}

//Send Queued pkt after ARP is resolved
func sendDLQueuedPkts(entry ARPEntry, dstPort uint16) {
	for {
		items, err := dlPktsQueue.Get(10)
		if err == nil {
			for _, item := range items {
				pkt := item.(*packet.Packet)
				copy(pkt.Ether.DAddr[:], entry.MAC)
				//common.LogInfo(common.Info, "[DL] Sending queued pkts ", pkt)
				result := pkt.SendPacket(dstPort)
				if result == true {
					atomic.AddUint64(&global.DlTxCounter, 1)
					//common.LogInfo(common.Info, "Sending success")
				} else {
					common.LogInfo(common.Info, "Sending failed ")
				}
			}
		}
		if dlPktsQueue.Len() == 0 {
			break
		}
	}
	common.LogInfo(common.Info, "[DL] Sending queued pkts ", dlPktsQueue.Len())
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
