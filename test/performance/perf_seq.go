// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var (
	load uint
)

func main() {
	var err error
	var mode uint
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	flag.UintVar(&mode, "mode", 2, "Benching mode: 2, 12 - two handles; 3, 13 - tree handles; 4, 14 - four handles. 2,3,4 - one flow; 12,13,14 - two flows")
	outport := flag.Uint("outport", 1, "port for sender")
	inport := flag.Uint("inport", 0, "port for receiver")
	noscheduler := flag.Bool("no-scheduler", false, "disable scheduler")
	dpdkLogLevel := flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	cores := flag.String("cores", "0-43", "Cores mask. Avoid hyperthreading here")
	flag.Parse()

	// Initialize NFF-GO library
	config := flow.Config{
		DisableScheduler: *noscheduler,
		DPDKArgs:         []string{*dpdkLogLevel},
		CPUList:          *cores,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	var tempFlow *flow.Flow
	var afterFlow *flow.Flow

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow, err := flow.SetReceiver(uint16(*inport))
	flow.CheckFatal(err)

	if mode > 10 {
		tempFlow, err = flow.SetPartitioner(firstFlow, 150, 150)
		flow.CheckFatal(err)
	}

	// Handle second flow via some heavy function
	flow.CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))
	flow.CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))
	if mode%10 > 2 {
		flow.CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))
	}
	if mode%10 > 3 {
		flow.CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))
	}
	if mode > 10 {
		flow.CheckFatal(flow.SetHandler(tempFlow, heavyFunc, nil))
		flow.CheckFatal(flow.SetHandler(tempFlow, heavyFunc, nil))
		if mode%10 > 2 {
			flow.CheckFatal(flow.SetHandler(tempFlow, heavyFunc, nil))
		}
		if mode%10 > 3 {
			flow.CheckFatal(flow.SetHandler(tempFlow, heavyFunc, nil))
		}
		afterFlow, err = flow.SetMerger(firstFlow, tempFlow)
		flow.CheckFatal(err)
	} else {
		afterFlow = firstFlow
	}

	flow.CheckFatal(flow.SetSender(afterFlow, uint16(*outport)))

	flow.CheckFatal(flow.SystemStart())
}

func heavyFunc(currentPacket *packet.Packet, context flow.UserContext) {
	currentPacket.ParseL3()
	ipv4 := currentPacket.GetIPv4()
	if ipv4 != nil {
		T := (ipv4.DstAddr)
		for j := uint(0); j < load; j++ {
			T += common.IPv4Address(j)
		}
		ipv4.SrcAddr = 263 + (T)
	}
}
