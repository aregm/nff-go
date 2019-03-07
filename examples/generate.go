// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"time"
)

func main() {
	mode := flag.Int("mode", 2, "mode of generating:\n0 - fast generate that will be slowed in a second.\n1 - time-based generate send by 32 packets.\n2 - time-based generate send by 1 packet.")
	output := flag.Int("port", 1, "output port")
	flag.Parse()
	outputPort := uint16(*output)

	flow.SystemInit(nil)

	switch *mode {
	case 0:
		firstFlow, genChannel, _ := flow.SetFastGenerator(generatePacket, 3500, nil)
		flow.CheckFatal(flow.SetSender(firstFlow, outputPort))
		go updateSpeed(genChannel)
		flow.SystemStart()
	case 1:
		firstFlow := flow.SetGenerator(generatePacket1, nil)
		flow.CheckFatal(flow.SetSender(firstFlow, outputPort))
		flow.SystemStart()
	case 2:
		temp, _ := (flow.SetReceiver(outputPort))
		flow.SetStopper(temp)
		flow.SystemInitPortsAndMemory()
		generatePacket2(outputPort)
	}
}

func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	packet.InitEmptyIPv4Packet(pkt, 1300)
	pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
}

func generatePacket1(pkt *packet.Packet, context flow.UserContext) {
	packet.InitEmptyIPv4Packet(pkt, 1300)
	pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	time.Sleep(175 * time.Microsecond)
}

func generatePacket2(port uint16) {
	for {
		pkt, _ := packet.NewPacket()
		packet.InitEmptyIPv4Packet(pkt, 1300)
		pkt.Ether.DAddr = [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
		pkt.SendPacket(port)
		time.Sleep(175 * time.Microsecond)
	}
}

func updateSpeed(genChannel chan uint64) {
	var load int
	for {
		// Can be file or any other source
		if _, err := fmt.Scanf("%d", &load); err == nil {
			genChannel <- uint64(load)
		}
	}
}
