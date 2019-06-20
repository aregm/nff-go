// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"

	"github.com/intel-go/nff-go/examples/nffPktgen/generator"
)

type GTPUConfig struct {
	IPv4      generator.IPv4Config `json:"ipv4"`
	StartTEID uint32               `json:"start-teid"`
	MaxTEIDs  uint32               `json:"max-teids"`
}

type IpPort struct {
	Index         uint16                    `json:"index"`
	DstMacAddress types.MACAddress          `json:"dst-mac"`
	Speed         uint64                    `json:"speed"`
	TrafficConfig generator.GeneratorConfig `json:"traffic-config"`
	// GTPUConfig is ignored for SGi port
	GTPUConfig *GTPUConfig `json:"gtp-u-config"`
	// DUTSGiIPv4 is ignored for S1u port
	DUTSGiIPv4 types.IPv4Address `json:"dut-sgi-ipv4"`

	staticARP   bool
	neighCache  *packet.NeighboursLookupTable
	macAddress  types.MACAddress
	teidCount   uint32
	packetCount uint64
	bytesCount  uint64
}

type GenConfig struct {
	S1uPort *IpPort `json:"s1u-port"`
	SgiPort *IpPort `json:"sgi-port"`
}

type HandlerContext struct {
	port *IpPort
}

func (hc HandlerContext) Copy() interface{} {
	return HandlerContext{
		port: hc.port,
	}
}

func (hc HandlerContext) Delete() {
}

func main() {
	genConfig := flag.String("c", "config.json", "specifies config for generator")
	testTime := flag.Uint("t", 30, "run generator for specified period of time in seconds, use zero to run forever")
	statInterval := flag.Uint("s", 2, "statistics update interval in seconds, use zero to disable it")
	flag.Parse()

	file, err := os.Open(*genConfig)
	if err != nil {
		panic(err)
	}
	decoder := json.NewDecoder(file)
	var gc GenConfig
	err = decoder.Decode(&gc)
	if err != nil {
		panic(fmt.Errorf("%s config reading failed: %v", *genConfig, err))
	}
	err = validateConfig(&gc)
	if err != nil {
		panic(err)
	}

	config := flow.Config{}
	flow.CheckFatal(flow.SystemInit(&config))

	if gc.S1uPort != nil {
		initPortFlows(gc.S1uPort, gc.S1uPort.GTPUConfig.IPv4.SAddr, true)
	}
	if gc.SgiPort != nil {
		initPortFlows(gc.SgiPort, gc.SgiPort.TrafficConfig[0].Config.Ether.IPv4.SAddr, false)
	}

	go func() {
		flow.CheckFatal(flow.SystemStart())
	}()

	// Set up finish channels
	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, os.Interrupt)

	var finishChannel, statsChannel <-chan time.Time
	if *testTime > 0 {
		finishChannel = time.NewTicker(time.Duration(*testTime) * time.Second).C
	}
	if *statInterval > 0 {
		statsChannel = time.NewTicker(time.Duration(*statInterval) * time.Second).C
	}

	started := time.Now()
out:
	for {
		select {
		case sig := <-interruptChannel:
			fmt.Printf("Received signal %v, finishing.\n", sig)
			break out
		case <-finishChannel:
			fmt.Println("Test timeout reached")
			break out
		case <-statsChannel:
			printStats(&gc, started)
		}
	}
	printStats(&gc, started)
	printTotals(&gc, started)
}

func validateConfig(gc *GenConfig) error {
	if gc.S1uPort != nil {
		if len(gc.S1uPort.TrafficConfig) > 1 {
			return fmt.Errorf("Currently suppotted mix only of one traffic configuration for S1u interface. Configured %d instead", len(gc.S1uPort.TrafficConfig))
		}
		if gc.S1uPort.GTPUConfig == nil {
			return fmt.Errorf("GTP config should be specified for S1u")
		}
		if gc.S1uPort.GTPUConfig.MaxTEIDs == 0 {
			return fmt.Errorf("GTP configuration should specify non-zero maximum number of possible TEIDs")
		}
		if gc.S1uPort.TrafficConfig[0].Config.DType != generator.ETHERHDR {
			return fmt.Errorf("Only \"ether\" type of traffic is supported for l2")
		}
		if gc.S1uPort.TrafficConfig[0].Config.Ether.DType != generator.IPv4HDR {
			return fmt.Errorf("Only \"ipv4\" type of traffic is supported for l3")
		}
	}
	if gc.SgiPort != nil {
		if len(gc.S1uPort.TrafficConfig) > 1 {
			return fmt.Errorf("Currently suppotted mix only of one traffic configuration for SGi interface. Configured %d instead", len(gc.SgiPort.TrafficConfig))
		}
		if gc.SgiPort.GTPUConfig != nil {
			return fmt.Errorf("GTP config cannot be specified for SGi interface")
		}
		if gc.SgiPort.TrafficConfig[0].Config.DType != generator.ETHERHDR {
			return fmt.Errorf("Only \"ether\" type of traffic is supported for l2")
		}
		if gc.SgiPort.TrafficConfig[0].Config.Ether.DType != generator.IPv4HDR {
			return fmt.Errorf("Only \"ipv4\" type of traffic is supported for l3")
		}
	}
	if gc.S1uPort == nil && gc.SgiPort == nil {
		return fmt.Errorf("Configuration should specify settings either for S1u interface or Sgi interface or both")
	}
	return nil
}

func initPortFlows(port *IpPort, myIPs generator.AddrRange, addEncapsulation bool) {
	port.macAddress = flow.GetPortMACAddress(port.Index)
	port.staticARP = port.DstMacAddress != types.MACAddress{0, 0, 0, 0, 0, 0}
	port.teidCount = 0
	// myIPs is caputred inside this lambda
	myV4Checker := func(ip types.IPv4Address) bool {
		return (myIPs.Inc != 0 && myIPs.Min <= uint64(packet.SwapBytesIPv4Addr(ip)) && myIPs.Max >= uint64(packet.SwapBytesIPv4Addr(ip))) ||
			(myIPs.Inc == 0 && myIPs.Current == uint64(packet.SwapBytesIPv4Addr(ip)))
	}
	port.neighCache = packet.NewNeighbourTable(port.Index, port.macAddress, myV4Checker, nil)

	// Output flow
	context, err := generator.GetContext(port.TrafficConfig)
	flow.CheckFatal(err)
	outFlow, _, err := flow.SetFastGenerator(generator.Generate, port.Speed, context)
	flow.CheckFatal(err)
	hc := HandlerContext{
		port: port,
	}
	if addEncapsulation {
		flow.CheckFatal(flow.SetHandlerDrop(outFlow, encapsulateGTP, hc))
	} else {
		flow.CheckFatal(flow.SetHandlerDrop(outFlow, setCorrectL2, hc))
	}
	flow.CheckFatal(flow.SetSender(outFlow, uint16(port.Index)))
	// Input flow
	inFlow, err := flow.SetReceiver(port.Index)
	flow.CheckFatal(flow.SetHandlerDrop(inFlow, receiveHandler, hc))
	flow.CheckFatal(flow.SetStopper(inFlow))
}

func encapsulateGTP(pkt *packet.Packet, ctx flow.UserContext) bool {
	hc := ctx.(HandlerContext)

	// Get destination IP address and compare it with minimal value
	pkt.ParseL3()
	ipv4 := pkt.GetIPv4NoCheck()
	if hc.port.teidCount == hc.port.GTPUConfig.MaxTEIDs {
		hc.port.teidCount = 0
	} else {
		hc.port.teidCount++
	}

	// Add new IPv4, UDP and GTP headers to the packet
	if !pkt.EncapsulateIPv4GTP(hc.port.teidCount + hc.port.GTPUConfig.StartTEID) {
		fmt.Println("EncapsulateHead returned error")
		return false
	}
	pkt.ParseL3()

	// Fill new IPv4 header with addresses according to configuration
	generator.FillIPv4Hdr(pkt, &hc.port.GTPUConfig.IPv4)
	ipv4 = pkt.GetIPv4NoCheck()

	// Fill L2
	pkt.Ether.EtherType = types.SwapIPV4Number
	pkt.Ether.SAddr = hc.port.macAddress
	if hc.port.staticARP {
		pkt.Ether.DAddr = hc.port.DstMacAddress
	} else {
		// Find l2 addresses for new destionation IP in ARP cache
		targetIP := ipv4.DstAddr
		targetMAC, found := hc.port.neighCache.LookupMACForIPv4(targetIP)
		if !found {
			// fmt.Println("Not found MAC address for IP", targetIP.String())
			hc.port.neighCache.SendARPRequestForIPv4(targetIP, ipv4.SrcAddr, 0)
			return false
		}
		pkt.Ether.DAddr = targetMAC
	}

	// Fill up l3
	ipv4.VersionIhl = 0x45
	ipv4.TypeOfService = 0
	ipv4.PacketID = 0x1513
	ipv4.FragmentOffset = 0
	ipv4.TimeToLive = 64

	length := pkt.GetPacketLen()
	ipv4.TotalLength = packet.SwapBytesUint16(uint16(length - types.EtherLen))
	ipv4.NextProtoID = types.UDPNumber
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))

	// Fill up L4
	pkt.ParseL4ForIPv4()
	udp := pkt.GetUDPForIPv4()
	udp.SrcPort = packet.SwapBytesUint16(packet.UDPPortGTPU)
	udp.DstPort = packet.SwapBytesUint16(packet.UDPPortGTPU)
	udp.DgramLen = packet.SwapBytesUint16(uint16(length - types.EtherLen - types.IPv4MinLen))
	pkt.ParseL7(types.UDPNumber)
	// Calculate checksums
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	udp.DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(ipv4, udp, pkt.Data))

	return true
}

func setCorrectL2(pkt *packet.Packet, ctx flow.UserContext) bool {
	hc := ctx.(HandlerContext)

	pkt.ParseL3()

	// Fill L2
	pkt.Ether.SAddr = hc.port.macAddress
	if hc.port.staticARP {
		pkt.Ether.DAddr = hc.port.DstMacAddress
	} else {
		// Set destination MAC address to DUT's SGi port, so it
		// effectively routes a packet to GW IP SGi address
		targetMAC, found := hc.port.neighCache.LookupMACForIPv4(hc.port.DUTSGiIPv4)
		if !found {
			// fmt.Println("Not found MAC address for IP", targetIP.String())
			hc.port.neighCache.SendARPRequestForIPv4(hc.port.DUTSGiIPv4, pkt.GetIPv4NoCheck().SrcAddr, 0)
			return false
		}
		pkt.Ether.DAddr = targetMAC
	}
	return true
}

func receiveHandler(pkt *packet.Packet, ctx flow.UserContext) bool {
	hc := ctx.(HandlerContext)

	pkt.ParseL3()
	protocol := pkt.Ether.EtherType

	if protocol == types.SwapARPNumber {
		err := hc.port.neighCache.HandleIPv4ARPPacket(pkt)
		if err != nil {
			fmt.Println(err)
		}
		return false
	}
	atomic.AddUint64(&hc.port.packetCount, 1)
	atomic.AddUint64(&hc.port.bytesCount, uint64(pkt.GetPacketLen()))
	return true
}

func printStats(gc *GenConfig, started time.Time) {
	fmt.Printf("%v: ", time.Since(started))
	if gc.S1uPort != nil {
		fmt.Printf("S1u received %vpkts, %vkB", gc.S1uPort.packetCount, gc.S1uPort.bytesCount/1000)
	}
	if gc.SgiPort != nil {
		if gc.S1uPort != nil {
			fmt.Print(". ")
		}
		fmt.Printf("Sgi received %vpkts, %vkB", gc.SgiPort.packetCount, gc.SgiPort.bytesCount/1000)
	}
	fmt.Println()
}

func printTotals(gc *GenConfig, started time.Time) {
	runtime := time.Since(started)
	runtimeint := uint64(runtime) / uint64(time.Second)
	fmt.Printf("\nTest executed for %v\n", runtime)
	if gc.S1uPort != nil {
		fmt.Printf("S1u pkts/s: %v\n", gc.S1uPort.packetCount/runtimeint)
		fmt.Printf("S1u kB/s: %v\n", gc.S1uPort.bytesCount/runtimeint/1000)
	}
	if gc.SgiPort != nil {
		fmt.Printf("Sgi pkts/s: %v\n", gc.SgiPort.packetCount/runtimeint)
		fmt.Printf("Sgi kB/s: %v\n", gc.SgiPort.bytesCount/runtimeint/1000)
	}
}
