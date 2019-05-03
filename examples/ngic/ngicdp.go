//Package dp ...
// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// NGIC Data plane with KNI
//   S1U interface : east traffic (GTP-U)
//   SGI interface : west traffic (UDP)
//
//                    +------------------+
// Uplink (UL)        |                  |
//       ------------>+                  +---------->
//                    |                  |
//          GTPU      | S1U           SGI|  UDP
//                    |                  |
// Downlink(DL)       |                  |
//       <------------+                  +<----------
//                    +------------------+
//
// UL Flow:
//   1. GTPU traffic recived on S1U interface (S1u recv flow) is validated based on the TEID and DestIP
//   2. If valid decap GTP headers
//   3. Apply the policy and charging rules
//   4. Update the next hop info for the pkt
//	    a) if StaticARP is enabled then lookup static arp table using destIP if found update the pkt with destination mac
//		 and send via SGI interface (SGI send flow) else drop the pkt.
//      b) if Static ARP is disabled
//		   i)If arp  entry not present in the arp table then
//			   -- Lookup the route table and check GW is present if not then create an arp pkt with the destIP
//		   	   -- else check the arp table if the GW ip entry is present if it then update destination mac as Gw mac.
//		   			and send it via SGI interface (SGI send flow),
//		   ii) else then create an ARP Entry in the ARP table with Status Incomplete add the pkt in the UL queue.
//			   create the arp pkt and send it via SGI interface (SGI send flow)
//	    c) In case the arp entry present but, Status=INCOMPLETE then add the pkt to queue
// Note : Before adding the pkt to queue. Clone the pkt and put the cloned pkt into queue.
// UL KNI Flow:
//    1. Check for the ARP/ICMP pkts
//    2. If ARP response is received and static ARP is disabled then, Update the ARP table with
//		ARP entry Status as COMPLETE
//    3. If there are any pkts on the Queue then update the next hope info and send the pkts to destination using
//      packet.SendPacket() method.
//
// Same flow is repeated for DL traffic only differance is DL traffic is UDP so, while fowarding pkt needs to encapsulated
// with GTPU headers
//
// For UEContexts/Session map is being used UlMap and DlMap.where, there is CP Simulator code which takes the configuration
// and construct the UlMap and DlMap entries.

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/examples/ngic/darp"
	"github.com/intel-go/nff-go/examples/ngic/nbserver"
	"github.com/intel-go/nff-go/examples/ngic/sarp"
	"github.com/intel-go/nff-go/examples/ngic/simucp"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/rules"
	"github.com/intel-go/nff-go/types"
)

//
// Config data plane Configuration option structure
type Config struct {
	NeedKNI         bool
	CPUList         string
	KNICpuIdx       string
	EnableDebugLog  bool
	EnableFlowDebug bool
	S1uPortIdx      uint16
	SgiPortIdx      uint16
	S1uIP           types.IPv4Address
	SgiIP           types.IPv4Address
	S1uDeviceName   string
	SgiDeviceName   string
	Memory          string
	NoStats         bool
}

// constants for rule file paths
const (
	pccRulesFilePath = "config/pcc_rules.cfg"
	sdfRulesFilePath = "config/sdf_rules.cfg"
	adcRulesFilePath = "config/adc_rules.cfg"
)

var (
	//dpConfig dp configuration object
	dpConfig = Config{}

	//sgiMac ...
	sgiMac types.MACAddress
	//s1uMac ...
	s1uMac types.MACAddress

	//sdfUlL3Rules ...
	sdfUlL3Rules *packet.L3Rules
	//sdfDlL3Rules ...
	sdfDlL3Rules *packet.L3Rules
	//adcL3Rules ...
	adcL3Rules *packet.L3Rules

	//EnableStaticARP  compile time flag to enable static arp
	EnableStaticARP string
	//RunCPSimu  compile time flag to run CP Simu
	RunCPSimu string
	//EnablePcap compile time flag to enable pcap
	EnablePcap string
)

// stats counters
var (
	ulRxCounter uint64
	dlRxCounter uint64
)

//kni counters
var (
	kniUlRxCounter uint64
	kniDlRxCounter uint64
	kniUlTxCounter uint64
	KniDlTxCounter uint64
)

//initConfig
func initConfig() {
	flag.BoolVar(&dpConfig.NeedKNI, "kni", false, "need kni support")
	flag.BoolVar(&dpConfig.EnableDebugLog, "debug", false, "enable debug log")
	flag.BoolVar(&dpConfig.EnableFlowDebug, "flow_debug", false, "enable flow  debug log")
	s1uPort := flag.Uint("s1u_port", 0, "s1u port idx")
	sgiPort := flag.Uint("sgi_port", 1, "sgi port idx")
	s1uIP := flag.String("s1u_ip", "", "s1u ip")
	sgiIP := flag.String("sgi_ip", "", "s1u ip")

	flag.StringVar(&dpConfig.S1uDeviceName, "s1u_dev", "S1UDev", "kni device name for s1u")
	flag.StringVar(&dpConfig.SgiDeviceName, "sgi_dev", "SGIDev", "kni device name for sgi")
	flag.StringVar(&dpConfig.CPUList, "cpu_list", "", "cpu list")
	flag.StringVar(&dpConfig.Memory, "memory", "512,4096", "memory")
	flag.BoolVar(&dpConfig.NoStats, "nostats", false, "Disable statics HTTP server.")

	flag.Parse()

	dpConfig.S1uPortIdx = uint16(*s1uPort)
	dpConfig.SgiPortIdx = uint16(*sgiPort)
	dpConfig.S1uIP = types.StringToIPv4(*s1uIP)
	dpConfig.SgiIP = types.StringToIPv4(*sgiIP)
	fmt.Printf("[INFO] S1uPortIdx = %v , SgiPortIdx = %v  \n", dpConfig.S1uPortIdx, dpConfig.SgiPortIdx)
	fmt.Printf("[INFO] S1uIP = %v , SgiIP = %v  \n", dpConfig.S1uIP, dpConfig.SgiIP)
	fmt.Printf("[INFO] KNI = %v , CPU_LIST %s , kniCpuIdx = %v  \n", dpConfig.NeedKNI, dpConfig.CPUList, dpConfig.KNICpuIdx)
	fmt.Printf("[INFO] S1uDeviceName = %s , SgiDeviceName = %s \n", dpConfig.S1uDeviceName, dpConfig.SgiDeviceName)
}

// intialize dp logger
func initLogger() {
	if _, err := os.Stat("log"); os.IsNotExist(err) {
		os.Mkdir("log", 0666)
	}

	file, err := os.OpenFile("log/dp.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Failed to open log file file.log : ", err)
		os.Exit(1)
	}
	common.SetLogger(file, "", log.Ldate|log.Ltime)
}

//initialize static rules
func initRules() {

	pccFilters := rules.ParsePCCRules(pccRulesFilePath)
	sdfFilters := rules.ParseSDFRules(sdfRulesFilePath)
	adcFilters := rules.ParseADCRules(adcRulesFilePath)
	rules.PrepareSdfUlACL(sdfFilters)
	rules.PrepareSdfDlACL(sdfFilters)
	rules.PrepareAdcACL(adcFilters)
	rules.BuildPCCSDFMap(pccFilters)
	rules.BuildPCCADCMap(pccFilters)

}

// Start dp
func main() {

	//intialize config
	initConfig()
	//setup log level DP logging set to INFO
	FlowLogType := common.No | common.Initialization | common.Info
	if dpConfig.EnableDebugLog == true {
		FlowLogType = common.No | common.Initialization | common.Info | common.Debug
	}
	if dpConfig.EnableFlowDebug == true {
		FlowLogType = common.No | common.Initialization | common.Info
	}
	common.SetLogType(FlowLogType)
	//intialize logger
	//	initLogger()
	//initialize rules
	initRules()
	// train DP
	go nbserver.Start()
	if RunCPSimu == "true" {
		go simucp.TrainDP()
	}

	if EnableStaticARP == "true" {
		sarp.Configure()
	} else {
		darp.Configure()
	}

	dpdkArgs := []string{"-l", dpConfig.CPUList, "--socket-mem", dpConfig.Memory, "--file-prefix", "dp"}

	fmt.Println("******* DP configured successfully *******")

	var statsServerAddres *net.TCPAddr = nil
	if !dpConfig.NoStats {
		statsServerAddres = &net.TCPAddr{
			Port: 8080,
		}
	}

	//set the flow configuration
	flowConfig := flow.Config{
		StatsHTTPAddress: statsServerAddres,
		NeedKNI:          dpConfig.NeedKNI,
		CPUList:          dpConfig.CPUList,
		LogType:          FlowLogType,
		DPDKArgs:         dpdkArgs,
		DisableScheduler: true,
	}

	//Initialize system
	flow.CheckFatal(flow.SystemInit(&flowConfig))
	s1uMac = flow.GetPortMACAddress(dpConfig.S1uPortIdx)
	sgiMac = flow.GetPortMACAddress(dpConfig.SgiPortIdx)

	fmt.Println("[INFO] S1U port MAC : ", s1uMac.String())
	fmt.Println("[INFO] SGI port MAC : ", sgiMac.String())

	var err1 error
	sdfUlL3Rules, err1 = packet.GetL3ACLFromORIG(rules.SdfUlACLFilePath)
	flow.CheckFatal(err1)
	sdfDlL3Rules, err1 = packet.GetL3ACLFromORIG(rules.SdfDlACLFilePath)
	flow.CheckFatal(err1)
	adcL3Rules, err1 = packet.GetL3ACLFromORIG(rules.AdcACLFilePath)
	flow.CheckFatal(err1)

	if dpConfig.NeedKNI == true {
		// create KNI Tap
		s1uKniDev, err := flow.CreateKniDevice(dpConfig.S1uPortIdx, dpConfig.S1uDeviceName)
		flow.CheckFatal(err)
		sgiKniDev, err := flow.CreateKniDevice(dpConfig.SgiPortIdx, dpConfig.SgiDeviceName)
		flow.CheckFatal(err)

		//set receiver on S1U port
		s1uEthInFlow, _ := flow.SetReceiver(dpConfig.S1uPortIdx)
		//set receiver on SGi port
		sgiEthInFlow, _ := flow.SetReceiver(dpConfig.SgiPortIdx)

		// set receiver on KNI Tap
		s1uKniInFlow := flow.SetReceiverKNI(s1uKniDev)
		sgiKniInFlow := flow.SetReceiverKNI(sgiKniDev)

		// Filter traffic
		toS1uKniFlow, err := flow.SetSeparator(s1uEthInFlow, S1uFilter, nil)
		toSgiKniFlow, err := flow.SetSeparator(sgiEthInFlow, SgiFilter, nil)

		flow.SetHandlerDrop(toS1uKniFlow, UplinkFilterKni, nil)
		flow.SetHandlerDrop(toSgiKniFlow, DownlinkFilterKni, nil)

		//send invalid pkts > knidev
		flow.CheckFatal(flow.SetSenderKNI(toS1uKniFlow, s1uKniDev))
		flow.CheckFatal(flow.SetSenderKNI(toSgiKniFlow, sgiKniDev))

		// merge the flows
		s1uOutFlow, err := flow.SetMerger(sgiEthInFlow, s1uKniInFlow)
		flow.CheckFatal(err)
		sgiOutFlow, err := flow.SetMerger(s1uEthInFlow, sgiKniInFlow)
		flow.CheckFatal(err)

		if EnablePcap == "true" {
			s1updp := pcapdumperParameters{fileName: "s1u"}
			sgipdp := pcapdumperParameters{fileName: "sgi"}
			flow.CheckFatal(flow.SetHandler(s1uOutFlow, pcapdumper, &s1updp))
			flow.CheckFatal(flow.SetHandler(sgiOutFlow, pcapdumper, &sgipdp))
		}

		//set sender on S1U
		flow.SetSender(s1uOutFlow, dpConfig.S1uPortIdx)
		//set sender on SGi
		flow.SetSender(sgiOutFlow, dpConfig.SgiPortIdx)

	} else {

		//set receiver on S1U port
		s1uEthInFlow, err := flow.SetReceiver(dpConfig.S1uPortIdx)
		flow.CheckFatal(err)
		//set receiver on SGi port
		sgiEthInFlow, err := flow.SetReceiver(dpConfig.SgiPortIdx)
		flow.CheckFatal(err)

		// Filter traffic
		flow.SetHandlerDrop(s1uEthInFlow, S1uFilter, nil)
		flow.SetHandlerDrop(sgiEthInFlow, SgiFilter, nil)

		//set sender on S1U
		flow.SetSender(sgiEthInFlow, dpConfig.S1uPortIdx)
		//set sender on SGi
		flow.SetSender(s1uEthInFlow, dpConfig.SgiPortIdx)

	}

	fmt.Println("******* DP started successfully *********")
	go PrintStats()

	flow.CheckFatal(flow.SystemStart())
} //

//DownlinkFilterKni ...
func DownlinkFilterKni(current *packet.Packet, context flow.UserContext) bool {
	atomic.AddUint64(&kniDlRxCounter, 1)
	ipv4, ipv6, arpPkt := current.ParseAllKnownL3()
	//	common.LogInfo(common.Info, "In SGI FilterFunction ", ipv4, arpPkt)
	if arpPkt != nil {
		if EnableStaticARP != "true" && arpPkt.Operation == 512 {
			common.LogInfo(common.Info, "ARP Response recv = ", arpPkt)
			darp.UpdateUlArpTable(arpPkt, dpConfig.SgiPortIdx, dpConfig.SgiDeviceName)
		}
		atomic.AddUint64(&KniDlTxCounter, 1)
		return true
	} else if ipv4 != nil {

		if ipv4.NextProtoID == types.ICMPNumber {
			common.LogInfo(common.Info, "PING pkt found ")
			atomic.AddUint64(&KniDlTxCounter, 1)
			return true
		}
	} else if ipv6 != nil {
		if ipv6.Proto == types.ICMPNumber {
			atomic.AddUint64(&KniDlTxCounter, 1)
			return true
		}
	}
	return false
}

// Apply ADC/SDF rules
func applyDlRulesFilter(current *packet.Packet) bool {

	sdfIdx := current.L3ACLPort(sdfDlL3Rules)
	adcIdx := current.L3ACLPort(adcL3Rules)

	//	common.LogInfo(common.Info, "SDX Rule Idx  #", int(sdfIdx))
	//	common.LogInfo(common.Info, "ADC Rule Idx  #", int(adcIdx))

	pccFilter := rules.LookUpPCCRuleBySDF(int(sdfIdx))
	adcPCCFilter, err := rules.LookUpPCCRuleByADC(int(adcIdx))
	if err == nil {
		if pccFilter.Precedence > adcPCCFilter.Precedence {
			pccFilter = adcPCCFilter
		}
	}
	//sort in ascending order
	gateStatus := pccFilter.GateStatus

	if gateStatus == 0 {
		ipv4 := current.GetIPv4()
		common.LogError(common.Info, "DROPING PKT ", ipv4)
		return false
	}

	return true
}

// Updated packet's next hop info
func updateDlNextHopInfo(pkt *packet.Packet, ctx flow.UserContext, ipv4 *packet.IPv4Hdr) bool {

	// ARP lookup for S1U_GW_IP
	pkt.Ether.SAddr = s1uMac
	if EnableStaticARP == "true" {
		dmac, err := sarp.LookArpTable(uint32(ipv4.DstAddr), pkt)
		if err == nil {
			copy(pkt.Ether.DAddr[:], dmac)
			atomic.AddUint64(&darp.DlTxCounter, 1)
		} else {
			common.LogError(common.Info, "[DL] Failed to find MAC for ", ipv4.DstAddr)
			return false
		}
	} else {
		common.LogInfo(common.Info, "[DL] Lookup ARP entry ", ipv4.DstAddr)
		dmac, sendArp, err := darp.LookupDlArpTable(uint32(ipv4.DstAddr), pkt) //s1uGwMac
		if err == nil {
			copy(pkt.Ether.DAddr[:], dmac)
			atomic.AddUint64(&darp.DlTxCounter, 1)
		} else {
			if sendArp {
				common.LogInfo(common.Info, "[DL] Sending ARP request ", ipv4.DstAddr)
				clonePkt, err := packet.NewPacket()
				if err == nil {
					packet.InitARPRequestPacket(clonePkt, s1uMac, types.IPv4Address(dpConfig.S1uIP), ipv4.DstAddr)
					clonePkt.SendPacket(dpConfig.S1uPortIdx)
					return false
				} else {
					common.LogError(common.No, "[DL] FAILED TO CREATE APR PACKET")
				}
			}
			common.LogError(common.Info, "[DL] ARP not found queued/rejected ", ipv4.DstAddr)
			return false
		}
	}
	return true
}

//SgiFilter ...
func SgiFilter(current *packet.Packet, context flow.UserContext) bool {
	current.ParseL3()

	//check if valid pkt
	pktIpv4 := current.GetIPv4()

	if pktIpv4 == nil {
		common.LogError(common.Info, "[DL] Not a valid Ipv4 PKT: INVALID PKT REJECT")
		return false
	}
	atomic.AddUint64(&dlRxCounter, 1)

	session, ok := nbserver.DlMap.Load(uint32(pktIpv4.DstAddr))
	if ok == false {
		common.LogError(common.Info, "[DL] INVALID PKT REJECT: TEID not found for UE_IP ", pktIpv4.DstAddr)
		return false
	}

	if applyDlRulesFilter(current) == false {
		return false
	}

	if current.EncapsulateIPv4GTP(session.DlS1Info.EnbTeid) == false {
		common.LogError(common.Info, "[DL]Encapsulating GTP pkt ")
		return false
	}

	current.ParseL3()
	ipv4 := current.GetIPv4NoCheck()
	length := current.GetPacketLen()

	// construct iphdr
	ipv4.VersionIhl = 0x45
	ipv4.TypeOfService = 0
	ipv4.PacketID = 0x1513 //CHANGEME
	ipv4.FragmentOffset = 0
	ipv4.TimeToLive = 64

	ipv4.TotalLength = packet.SwapBytesUint16(uint16(length - types.EtherLen))
	ipv4.NextProtoID = types.UDPNumber

	ipv4.SrcAddr = types.IPv4Address(dpConfig.S1uIP)
	ipv4.DstAddr = types.IPv4Address(session.DlS1Info.EnbIP)
	ipv4.HdrChecksum = packet.CalculateIPv4Checksum(ipv4)

	current.ParseL4ForIPv4()
	udp := current.GetUDPNoCheck()

	// construct udphdr
	udp.SrcPort = packet.SwapUDPPortGTPU
	udp.DstPort = packet.SwapUDPPortGTPU
	udp.DgramLen = uint16(length - types.EtherLen - types.IPv4MinLen)
	udp.DgramCksum = 0

	if updateDlNextHopInfo(current, context, ipv4) == false {
		return false
	}
	return true
}

//UplinkFilterKni ...
func UplinkFilterKni(current *packet.Packet, context flow.UserContext) bool {

	atomic.AddUint64(&kniUlRxCounter, 1)

	ipv4, ipv6, arpPkt := current.ParseAllKnownL3()
	//	common.LogInfo(common.Info, "In S1U FilterFunction ", ipv4, arpPkt)
	if arpPkt != nil {
		if EnableStaticARP != "true" && arpPkt.Operation == 512 {
			common.LogInfo(common.Info, "ARP response recv = ", arpPkt)
			darp.UpdateDlArpTable(arpPkt, dpConfig.S1uPortIdx, dpConfig.S1uDeviceName)
		}
		atomic.AddUint64(&kniUlTxCounter, 1)
		return true
	} else if ipv4 != nil {

		if ipv4.NextProtoID == types.ICMPNumber {
			common.LogInfo(common.Info, "PING pkt found ")
			atomic.AddUint64(&kniUlTxCounter, 1)
			return true
		}
	} else if ipv6 != nil {
		if ipv6.Proto == types.ICMPNumber {
			atomic.AddUint64(&kniUlTxCounter, 1)
			return true
		}
	}
	return false
} //

// Apply ADC/SDF rules
func applyUlRulesFilter(current *packet.Packet) bool {

	sdfIdx := current.L3ACLPort(sdfUlL3Rules)
	adcIdx := current.L3ACLPort(adcL3Rules)
	//	common.LogInfo(common.Info, "SDX Rule Idx  #", int(sdf_idx))
	//	common.LogInfo(common.Info, "ADC Rule Idx  #", int(adc_idx))

	pccFilter := rules.LookUpPCCRuleBySDF(int(sdfIdx))
	adcPCCFilter, err := rules.LookUpPCCRuleByADC(int(adcIdx))
	if err == nil {
		if pccFilter.Precedence > adcPCCFilter.Precedence {
			pccFilter = adcPCCFilter
		}
	}
	//sort in ascending order
	gateStatus := pccFilter.GateStatus

	if gateStatus == 0 { //drop
		ipv4 := current.GetIPv4()
		common.LogError(common.Info, "DROPING PKT ", ipv4)
		return false
	}

	return true
}

// Updated packet's next hop info
func updateUlNextHopInfo(pkt *packet.Packet, ctx flow.UserContext, ipv4 *packet.IPv4Hdr) bool {
	// AiRP lookup for S1U_GW_IP
	pkt.Ether.SAddr = sgiMac

	if EnableStaticARP == "true" {
		//Lookup arp table
		dmac, err := sarp.LookArpTable(uint32(ipv4.DstAddr), pkt)
		if err == nil {
			copy(pkt.Ether.DAddr[:], dmac)
			atomic.AddUint64(&darp.UlTxCounter, 1)
		} else {
			common.LogError(common.Info, "[UL] Failed to find MAC for ", ipv4.DstAddr)
			return false
		}
	} else {
		common.LogInfo(common.Info, "[UL] Lookup ARP entry ", ipv4.DstAddr)
		//Lookup arp table
		dmac, sendArp, err := darp.LookupUlArpTable(uint32(ipv4.DstAddr), pkt) //sgiGwMac

		if err == nil {
			copy(pkt.Ether.DAddr[:], dmac)
			atomic.AddUint64(&darp.UlTxCounter, 1)
		} else {
			if sendArp {
				//sending arp request pkt only once
				common.LogInfo(common.Info, "[UL] Sending ARP request ", ipv4.DstAddr)
				clonePkt, err := packet.NewPacket()
				if err == nil {
					packet.InitARPRequestPacket(clonePkt, sgiMac, types.IPv4Address(dpConfig.SgiIP), ipv4.DstAddr)
					clonePkt.SendPacket(dpConfig.SgiPortIdx)
					return false
				} else {
					common.LogError(common.No, "[UL] FAILED TO CREATE APR PACKET")
				}
			}
			return false
		}
	}
	return true

}

//S1uFilter ...
//          Decap packet
//          Check if it's valid GTPU packet otherwise drop it
func S1uFilter(current *packet.Packet, context flow.UserContext) bool {
	current.ParseL3()
	ipv4 := current.GetIPv4()
	if ipv4 == nil || ipv4.DstAddr != dpConfig.S1uIP {
		// reject with wrong dest ip
		common.LogError(common.Info, " [UL] Not a ipv4 pkt or reject dest ip doesn't match", ipv4)
		if ipv4 != nil {
			common.LogError(common.Info, "[UL] reject dest ip doesn't match ", ipv4)
		}
		return false
	}

	current.ParseL4ForIPv4()
	udp := current.GetUDPForIPv4()

	if udp == nil || udp.DstPort != packet.SwapUDPPortGTPU {
		// reject un-tunneled packet
		common.LogError(common.Info, "[UL]rejecting un-tunneled packet")
		return false
	}
	gtpu := current.GTPIPv4FastParsing()

	if gtpu.TEID == 0 || gtpu.MessageType != packet.G_PDU {
		// reject for gtpu reasons
		common.LogError(common.Info, "[UL]rejecting not valid GTPU packet", ipv4)
		return false
	}
	atomic.AddUint64(&ulRxCounter, 1) //increment counters

	//make a copy of gtpu
	pktTEID := gtpu.TEID
	_, ok := nbserver.UlMap.Load(pktTEID)

	if ok == false {
		common.LogError(common.Info, "[UL] INVALID PKT REJECT: UE_CONEXT not found for TEID:",
			strconv.FormatInt(int64(packet.SwapBytesUint32(pktTEID)), 16), ", DestIP:", ipv4.DstAddr)
		return false

	}

	if current.DecapsulateIPv4GTP() == false {
		common.LogError(common.Info, "[UL] reject unable to decap GTPU header", ipv4)
		return false
	}

	current.ParseL3()
	ipv4 = current.GetIPv4()

	//apply rules
	if applyUlRulesFilter(current) == false {
		return false
	}
	//Lookup the dest mac and update the next hop info
	if updateUlNextHopInfo(current, context, ipv4) == false {
		return false
	}
	return true
}

//PrintStats print ul/dl stats every second
func PrintStats() {
	fmt.Printf("\n\t\tUPLINK\t\t\t\t\t   ||\t\tDOWNLINK")
	count := 0
	for {
		if count%20 == 0 {
			fmt.Printf("\n%-11s %-11s %-11s %-11s %-11s|| %-11s %-11s %-11s%-11s %-11s\n", "KNI-RX", "KNI-TX", "UL-RX", "UL-TX", "UL-DFF", "KNI-RX", "KNI-TX", "DL-RX", "DL-TX", "DL-DFF")
		}
		fmt.Printf("%-11d %-11d %-11d %-11d %-11d|| %-11d %-11d %-11d%-11d %-11d\n", kniUlRxCounter, kniUlTxCounter, ulRxCounter, darp.UlTxCounter, (ulRxCounter - darp.UlTxCounter), kniDlRxCounter, KniDlTxCounter, dlRxCounter, darp.DlTxCounter, (dlRxCounter - darp.DlTxCounter))
		time.Sleep(10 * 1000 * time.Millisecond)
		count++
	}
}

type pcapdumperParameters struct {
	f        *os.File
	fileName string
}

func (pd pcapdumperParameters) Copy() interface{} {
	fileObj := fmt.Sprintf("%s.pcap", pd.fileName)
	f, err := os.Create(fileObj)
	if err != nil {
		fmt.Println("Cannot create file: ", err)
		os.Exit(0)
	}
	if err := packet.WritePcapGlobalHdr(f); err != nil {
		log.Fatal(err)
	}
	pdp := pcapdumperParameters{f: f, fileName: pd.fileName}
	return pdp
}

func (pd pcapdumperParameters) Delete() {
	pd.f.Close()
}

func pcapdumper(currentPacket *packet.Packet, context flow.UserContext) {
	pd := context.(pcapdumperParameters)
	if err := currentPacket.WritePcapOnePacket(pd.f); err != nil {
		log.Fatal(err)
	}
}
