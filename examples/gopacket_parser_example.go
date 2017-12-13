// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var (
	printOn bool

	inport1     uint
	inport2     uint
	outport1    uint
	outport2    uint
	noscheduler bool
)

func main() {
	flag.BoolVar(&printOn, "print", false, "enable print of parsed layers")
	flag.UintVar(&outport1, "outport1", 1, "port for 1st sender")
	flag.UintVar(&outport2, "outport2", 1, "port for 2nd sender")
	flag.UintVar(&inport1, "inport1", 0, "port for 1st receiver")
	flag.UintVar(&inport2, "inport2", 0, "port for 2nd receiver")
	flag.BoolVar(&noscheduler, "no-scheduler", false, "disable scheduler")
	flag.Parse()

	// Initialize YANFF library at 15 cores by default
	config := flow.Config{
		CPUList:          "0-14",
		DisableScheduler: noscheduler,
	}
	flow.SystemInit(&config)

	// Receive packets from zero port. One queue per receive will be added automatically.
	firstFlow0 := flow.SetReceiver(uint8(inport1))
	firstFlow1 := flow.SetReceiver(uint8(inport2))

	firstFlow := flow.SetMerger(firstFlow0, firstFlow1)

	var ctx gopacketContext
	flow.SetHandler(firstFlow, gopacketHandleFunc, ctx)

	// Split for two senders and send
	secondFlow := flow.SetPartitioner(firstFlow, 150, 150)
	flow.SetSender(firstFlow, uint8(outport1))
	flow.SetSender(secondFlow, uint8(outport2))

	flow.SystemStart()
}

// Parser and pre-allocated layers to be parsed.
type gopacketContext struct {
	eth layers.Ethernet
	ip4 layers.IPv4
	ip6 layers.IPv6
	tcp layers.TCP
	udp layers.UDP

	parser *gopacket.DecodingLayerParser
}

// Each handler will use its own gopacketContext.
func (ctx gopacketContext) Copy() interface{} {
	newCtx := new(gopacketContext)
	newCtx.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &newCtx.eth, &newCtx.ip4, &newCtx.ip6, &newCtx.tcp, &newCtx.udp)
	return newCtx
}

func (ctx gopacketContext) Delete() {
}

func gopacketHandleFunc(currentPacket *packet.Packet, context flow.UserContext) {
	ctx := context.(*gopacketContext)
	parser := ctx.parser
	decoded := []gopacket.LayerType{}

	packetData := currentPacket.GetRawPacketBytes()
	parser.DecodeLayers(packetData, &decoded)

	if printOn {
		fmt.Println("--------- Packet----------")
		printLayersInfo(ctx, decoded)
	}
}

func printLayersInfo(ctx *gopacketContext, decoded []gopacket.LayerType) {
	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			fmt.Println("Ethernet layer detected.")
			fmt.Printf("	From %s to %s\n", ctx.eth.SrcMAC, ctx.eth.DstMAC)
			fmt.Printf("	Protocol: %v\n", ctx.eth.EthernetType)
		case layers.LayerTypeIPv4:
			fmt.Println("IPv4 layer detected.")
			fmt.Printf("	From %s to %s\n", ctx.ip4.SrcIP, ctx.ip4.DstIP)
			fmt.Printf("	Protocol: %v\n", ctx.ip4.Protocol)
		case layers.LayerTypeIPv6:
			fmt.Println("IPv6 layer detected.")
			fmt.Printf("	From %s to %s\n", ctx.ip6.SrcIP, ctx.ip6.DstIP)
			fmt.Printf("	Protocol: %v\n", ctx.ip6.NextHeader)
		case layers.LayerTypeTCP:
			fmt.Println("TCP layer detected.")
			fmt.Printf("	From port %d to %d\n", ctx.tcp.SrcPort, ctx.tcp.DstPort)
			fmt.Printf("	Sequence number: %d\n", ctx.tcp.Seq)
		case layers.LayerTypeUDP:
			fmt.Println("UDP layer detected.")
			fmt.Printf("	From port %d to %d\n", ctx.udp.SrcPort, ctx.udp.DstPort)
		}
	}
}
