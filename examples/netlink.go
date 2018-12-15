// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
)

// internal structures:
// LPM rules storage
var lpm *packet.LPM

// LPM binds ip with number and below
// is a struct to get ip by binded value
var portToIP []common.IPv4Address

// length of portToIp
var lenP2IP common.IPv4Address

func main() {
	inport := flag.Uint("inport", 0, "port for receiver")
	lpmSocket := flag.Uint("lpmSocket", 0, "create lpm structure at given socket")
	lpmMaxRules := flag.Uint64("lpmMaxRules", 100, "maximum number of LPM rules inside table")
	lpmMaxNumberTbl8 := flag.Uint64("lpmMaxNumberTbl8", 256*256, "maximum number of LPM rules with mask length more than 24 bits")
	cores := flag.String("cores", "0-7", "Specify CPU cores to use")
	flag.Parse()

	config := flow.Config{
		CPUList: *cores,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	initRouteCache(uint8(*lpmSocket), uint32(*lpmMaxRules), uint32(*lpmMaxNumberTbl8))

	go updateRouteCache()

	inputFlow, err := flow.SetReceiver(uint16(*inport))
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetHandler(inputFlow, handler, nil))

	flow.CheckFatal(flow.SetStopper(inputFlow))

	flow.CheckFatal(flow.SystemStart())
}

func handler(current *packet.Packet, ctx flow.UserContext) {
	ipv4, _, _ := current.ParseAllKnownL3()
	if ipv4 != nil {
		var next common.IPv4Address
		if lpm.Lookup(ipv4.DstAddr, &next) {
			common.LogDebug(common.Debug, "gateway for packet: ", common.IPv4ToBytes(portToIP[next]))
		}
	}
}

func netToNffIPv4(netIP net.IP) common.IPv4Address {
	if netIP == nil || len(netIP) != 4 {
		return 0
	}
	return common.BytesToIPv4(netIP[0], netIP[1], netIP[2], netIP[3])
}

func getIPAndDepth(netIP *net.IPNet) (common.IPv4Address, uint8, error) {
	var (
		ip    common.IPv4Address
		depth int
	)
	if netIP != nil {
		if len(netIP.IP) == 4 {
			ip = netToNffIPv4(netIP.IP)
			depth, _ = netIP.Mask.Size()
		} else {
			return 0, 0, fmt.Errorf("IPv6 is not supported, fail to add route, skip")
		}
	}
	if depth == 0 {
		depth = 1
	}
	return ip, uint8(depth), nil
}

func addLPM(v netlink.Route) {
	gw := netToNffIPv4(v.Gw)
	ip, depth, err := getIPAndDepth(v.Dst)
	if err != nil {
		common.LogWarning(common.Debug, err)
		return
	}
	portToIP = append(portToIP, gw)
	lenP2IP++
	common.LogDebug(common.Debug, "adding: ", ip, depth, lenP2IP-1)
	if err := lpm.Add(ip, depth, lenP2IP-1); err < 0 {
		common.LogFatal(common.Debug, "failed to add to lpm with ", err)
	}
}

func deleteLPM(v netlink.Route) {
	ip, depth, err := getIPAndDepth(v.Dst)
	if err != nil {
		common.LogWarning(common.Debug, err)
		return
	}
	if lpm.Delete(ip, depth) < 0 {
		common.LogFatal(common.Debug, "failed to delete from lpm")
	}
}

func initRouteCache(socket uint8, maxRules uint32, numberTbl8 uint32) {
	common.LogDebug(common.Debug, "------- Init Route Cache -------", socket, maxRules, numberTbl8)

	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		common.LogFatal(common.Debug, "Cannot list routs")
	}

	lpm = packet.CreateLPM("lpm", socket, maxRules, numberTbl8)
	if lpm == nil {
		common.LogFatal(common.Debug, "failed to create LPM struct")
	}
	for k, v := range routes {
		common.LogDebug(common.Debug, "Add route: ", k, v)
		addLPM(v)
	}
}

func printKernelRouteTable() {
	common.LogDebug(common.Debug, "------- Print Kernel Route Table -------")

	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		common.LogFatal(common.Debug, "Cannot list routs")
	}

	for k, v := range routes {
		common.LogDebug(common.Debug, "route: ", k, v)
	}
}

func updateRouteCache() {
	ch := make(chan netlink.RouteUpdate)
	done := make(chan struct{})

	defer close(done)

	if err := netlink.RouteSubscribe(ch, done); err != nil {
		common.LogFatal(common.Debug, "Cannot subscribe:", err)
	}

	for {
		timeout := time.After(2 * time.Second)
		select {
		case update := <-ch:
			if update.Type == unix.RTM_NEWROUTE {
				common.LogDebug(common.Debug, "========== Route added: ", update)
				addLPM(update.Route)
			}
			if update.Type == unix.RTM_DELROUTE && update.Route.Dst != nil && update.Route.Gw != nil {
				common.LogDebug(common.Debug, "========== Route deleted: ", update)
				deleteLPM(update.Route)
			}
		case <-timeout:
			common.LogDebug(common.Debug, "===== No changes after 2s =====")
			printKernelRouteTable()
		}
	}
}
