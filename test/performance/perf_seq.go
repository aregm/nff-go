// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var (
	load uint
	mode uint

	inport1     uint
	inport2     uint
	outport1    uint
	outport2    uint
	noscheduler bool
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	var err error
	flag.UintVar(&load, "load", 1000, "Use this for regulating 'load intensity', number of iterations")
	flag.UintVar(&mode, "mode", 2, "Benching mode: 2, 12 - two handles; 3, 13 - tree handles; 4, 14 - four handles. 2,3,4 - one flow; 12,13,14 - two flows")
	flag.UintVar(&outport1, "outport1", 1, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	flag.UintVar(&inport1, "inport1", 0, "port for 1st receiver")
	flag.UintVar(&inport2, "inport2", 0, "port for 2nd receiver")
	flag.BoolVar(&noscheduler, "no-scheduler", false, "disable scheduler")
	flag.Parse()

	// Initialize YANFF library at 35 cores by default
	config := flow.Config{
		CPUList:          "0-34",
		DisableScheduler: noscheduler,
	}
	CheckFatal(flow.SystemInit(&config))

	var tempFlow *flow.Flow
	var afterFlow *flow.Flow

	// Receive packets from zero port. One queue will be added automatically.
	firstFlow0, err := flow.SetReceiver(uint8(inport1))
	CheckFatal(err)
	firstFlow1, err := flow.SetReceiver(uint8(inport2))
	CheckFatal(err)

	firstFlow, err := flow.SetMerger(firstFlow0, firstFlow1)
	CheckFatal(err)

	if mode > 10 {
		tempFlow, err = flow.SetPartitioner(firstFlow, 150, 150)
		CheckFatal(err)
	}

	// Handle second flow via some heavy function
	CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))
	CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))
	if mode%10 > 2 {
		CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))
	}
	if mode%10 > 3 {
		CheckFatal(flow.SetHandler(firstFlow, heavyFunc, nil))
	}
	if mode > 10 {
		CheckFatal(flow.SetHandler(tempFlow, heavyFunc, nil))
		CheckFatal(flow.SetHandler(tempFlow, heavyFunc, nil))
		if mode%10 > 2 {
			CheckFatal(flow.SetHandler(tempFlow, heavyFunc, nil))
		}
		if mode%10 > 3 {
			CheckFatal(flow.SetHandler(tempFlow, heavyFunc, nil))
		}
		afterFlow, err = flow.SetMerger(firstFlow, tempFlow)
		CheckFatal(err)
	} else {
		afterFlow = firstFlow
	}
	secondFlow, err := flow.SetPartitioner(afterFlow, 150, 150)
	CheckFatal(err)

	// Send both flows each one to one port. Queues will be added automatically.
	CheckFatal(flow.SetSender(afterFlow, uint8(outport1)))
	CheckFatal(flow.SetSender(secondFlow, uint8(outport2)))

	CheckFatal(flow.SystemStart())
}

func heavyFunc(currentPacket *packet.Packet, context flow.UserContext) {
	currentPacket.ParseL3()
	ipv4 := currentPacket.GetIPv4()
	if ipv4 != nil {
		T := (ipv4.DstAddr)
		for j := uint(0); j < load; j++ {
			T += uint32(j)
		}
		ipv4.SrcAddr = 263 + (T)
	}
}
