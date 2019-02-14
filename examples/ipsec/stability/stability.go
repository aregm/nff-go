// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/nff-go/types"
import "github.com/intel-go/nff-go/flow"
import "github.com/intel-go/nff-go/packet"
import "github.com/intel-go/nff-go/examples/ipsec"
import "flag"
import "fmt"
import "time"

var step int

func main() {
	vector := flag.Bool("v", false, "vector version")
	mode := flag.Bool("m", false, "check encapsulation")
	flag.Parse()

	config := flow.Config{
		DisableScheduler: true,
	}
	flow.SystemInit(&config)

	var input *flow.Flow
	gen := flow.SetGenerator(gen, nil)
	flow.SetHandler(gen, dump_before, nil)
	if *mode {
		if *vector {
			flow.SetVectorHandlerDrop(gen, ipsec.VectorEncapsulation, ipsec.VContext{})
		} else {
			flow.SetHandlerDrop(gen, ipsec.ScalarEncapsulation, ipsec.SContext{})
		}
		flow.SetSender(gen, 1)
		input, _ = flow.SetReceiver(0)
	} else {
		flow.SetSender(gen, 0)
		input, _ = flow.SetReceiver(1)
		flow.SetHandlerDrop(input, ipsec.Decapsulation, ipsec.SContext{})
	}
	flow.SetHandler(input, dump_after, nil)
	flow.SetStopper(input)
	flow.SystemStart()
}

func gen(pkt *packet.Packet, context flow.UserContext) {
	packet.InitEmptyIPv4TCPPacket(pkt, 50)
	ipv4 := pkt.GetIPv4()
	tcp := pkt.GetTCPForIPv4()

	pkt.Ether.DAddr = [6]uint8{1, 2, 3, 4, 5, 6}
	pkt.Ether.SAddr = [6]uint8{1, 2, 3, 4, 5, 6}

	ipv4.SrcAddr = types.BytesToIPv4(111, 111, 111, 111)
	ipv4.DstAddr = types.BytesToIPv4(222, 222, 222, 222)

	tcp.SrcPort = packet.SwapBytesUint16(25)
	tcp.DstPort = packet.SwapBytesUint16(35)

	step++
	if step == 100 {
		time.Sleep(100 * time.Millisecond)
		step = 0
	}
}

func dump_before(currentPacket *packet.Packet, context flow.UserContext) {
	fmt.Printf("Raw bytes before=%x\n", currentPacket.GetRawPacketBytes())
}

func dump_after(currentPacket *packet.Packet, context flow.UserContext) {
	fmt.Printf("Raw bytes after =%x\n", currentPacket.GetRawPacketBytes())
}
