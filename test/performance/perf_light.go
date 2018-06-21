// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/test/stability/stabilityCommon"
)

func main() {
	var mode uint
	flag.UintVar(&mode, "mode", 0, "Benching mode: 0 - empty, 1 - parsing, 2 - parsing, reading, writing")
	inport1 := flag.Uint("inport1", 0, "port for receiver")
	inport2 := flag.Uint("inport2", 1, "port for receiver")
	// inport3 := flag.Uint("inport3", 2, "port for receiver")
	// inport4 := flag.Uint("inport4", 3, "port for receiver")
	noscheduler := flag.Bool("no-scheduler", false, "disable scheduler")
	dpdkLogLevel := flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	cores := flag.String("cores", "0-43", "Cores mask. Avoid hyperthreading here")
	configFile := flag.String("config", "", "Specify json config file name (mandatory for VM)")
	target := flag.String("target", "", "Target host name from config file (mandatory for VM)")
	flag.Parse()
	stabilityCommon.InitCommonState(*configFile, *target)
	
	// Initialize NFF-GO library
	config := flow.Config{
		DisableScheduler: *noscheduler,
		DPDKArgs:         []string{*dpdkLogLevel},
		CPUList:          *cores,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	// Receive packets from zero port. One queue per receive will be added automatically.
	firstFlow1, err := flow.SetReceiver(uint16(*inport1))
	flow.CheckFatal(err)
	firstFlow2, err := flow.SetReceiver(uint16(*inport2))
	flow.CheckFatal(err)
	// firstFlow3, err := flow.SetReceiver(uint16(*inport3))
	// flow.CheckFatal(err)
	// firstFlow4, err := flow.SetReceiver(uint16(*inport4))
	// flow.CheckFatal(err)
	// Handle second flow via some heavy function
	if mode == 0 {
		flow.CheckFatal(flow.SetHandler(firstFlow1, heavyFunc0, nil))
	} else if mode == 1 {
		flow.CheckFatal(flow.SetHandler(firstFlow1, heavyFunc1, nil))
	} else {
		flow.CheckFatal(flow.SetHandler(firstFlow1, heavyFunc2, nil))
	}
	flow.CheckFatal(flow.SetHandler(firstFlow1, fixMACAddrs, nil))
	
	flow.CheckFatal(flow.SetSender(firstFlow1, uint16(*inport1)))


	if mode == 0 {
		flow.CheckFatal(flow.SetHandler(firstFlow2, heavyFunc0, nil))
	} else if mode == 1 {
		flow.CheckFatal(flow.SetHandler(firstFlow2, heavyFunc1, nil))
	} else {
		flow.CheckFatal(flow.SetHandler(firstFlow2, heavyFunc2, nil))
	}
	flow.CheckFatal(flow.SetHandler(firstFlow2, fixMACAddrs, nil))
	
	flow.CheckFatal(flow.SetSender(firstFlow2, uint16(*inport2)))


	// if mode == 0 {
	// 	flow.CheckFatal(flow.SetHandler(firstFlow3, heavyFunc0, nil))
	// } else if mode == 1 {
	// 	flow.CheckFatal(flow.SetHandler(firstFlow3, heavyFunc1, nil))
	// } else {
	// 	flow.CheckFatal(flow.SetHandler(firstFlow3, heavyFunc2, nil))
	// }
	// flow.CheckFatal(flow.SetHandler(firstFlow3, fixMACAddrs, nil))
	
	// flow.CheckFatal(flow.SetSender(firstFlow3, uint16(*inport3)))

	// if mode == 0 {
	// 	flow.CheckFatal(flow.SetHandler(firstFlow4, heavyFunc0, nil))
	// } else if mode == 1 {
	// 	flow.CheckFatal(flow.SetHandler(firstFlow4, heavyFunc1, nil))
	// } else {
	// 	flow.CheckFatal(flow.SetHandler(firstFlow4, heavyFunc2, nil))
	// }
	// flow.CheckFatal(flow.SetHandler(firstFlow4, fixMACAddrs, nil))
	
	// flow.CheckFatal(flow.SetSender(firstFlow4, uint16(*inport4)))

	flow.CheckFatal(flow.SystemStart())
}

func fixMACAddrs(currentPacket *packet.Packet, context flow.UserContext) {
	//fmt.Printf("before: %x\n", currentPacket.GetRawPacketBytes())
	tmp := currentPacket.Ether.DAddr
	currentPacket.Ether.DAddr = currentPacket.Ether.SAddr
	currentPacket.Ether.SAddr = tmp
	currentPacket.ParseL3()
	if currentPacket.GetIPv4() != nil {
		T := currentPacket.GetIPv4().DstAddr
		(*packet.IPv4Hdr)(currentPacket.L3).DstAddr = currentPacket.GetIPv4().SrcAddr
		(*packet.IPv4Hdr)(currentPacket.L3).SrcAddr = T
	}
}

func heavyFunc0(currentPacket *packet.Packet, context flow.UserContext) {
}

func heavyFunc1(currentPacket *packet.Packet, context flow.UserContext) {
	currentPacket.ParseL3()
}

func heavyFunc2(currentPacket *packet.Packet, context flow.UserContext) {
	currentPacket.ParseL3()
	ipv4 := currentPacket.GetIPv4()
	if ipv4 != nil {
		T := ipv4.TimeToLive
		ipv4.TimeToLive = 0 + (T)
	}
}
