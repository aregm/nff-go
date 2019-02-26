// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

var size uint
var speed uint

type ctx struct {
	r uint16
}

func (c ctx) Copy() interface{} {
	n := new(ctx)
	n.r = 20
	return n
}

func (c ctx) Delete() {
}

func main() {
	flag.UintVar(&size, "s", 64, "size of packets")
	flag.UintVar(&speed, "v", 40000, "speed of generation")
	flag.Parse()

	pkts := uint64(speed * 1000 * 1000 / 8 / (size + 20))
	size = size - types.EtherLen - types.IPv4MinLen - types.TCPMinLen - 4 /* Ethernet checksum length*/

	flow.SystemInit(nil)

	a, _, _ := flow.SetFastGenerator(generatePacket, pkts/2, *new(ctx))
	b, _, _ := flow.SetFastGenerator(generatePacket, pkts/2, *new(ctx))

	flow.SetSender(a, 0)
	flow.SetSender(b, 0)

	flow.SystemStart()
}

// Function to use in generator
func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	ctx1 := context.(*ctx)
	r := ctx1.r
	packet.InitEmptyIPv4TCPPacket(pkt, size)
	ipv4 := pkt.GetIPv4()
	tcp := pkt.GetTCPForIPv4()

	ipv4.DstAddr = packet.SwapBytesIPv4Addr(types.IPv4Address(r))
	ipv4.SrcAddr = packet.SwapBytesIPv4Addr(types.IPv4Address(r + 15))

	tcp.DstPort = packet.SwapBytesUint16(r + 25)
	tcp.SrcPort = packet.SwapBytesUint16(r + 35)

	ctx1.r++
	if ctx1.r > 259 {
		ctx1.r = 20
	}
}
