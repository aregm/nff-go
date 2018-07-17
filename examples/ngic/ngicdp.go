//Package dp ...
// Copyright (c) 2017 Intel Corporation.
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
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/examples/ngic/darp"
	"github.com/intel-go/nff-go/examples/ngic/global"
	"github.com/intel-go/nff-go/examples/ngic/rule"
	"github.com/intel-go/nff-go/examples/ngic/sarp"
	"github.com/intel-go/nff-go/examples/ngic/simucp"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"log"
	"os"
	"sync/atomic"
	"time"
)

//
// Config data plane Configuration option structure
type Config struct {
	NeedKNI         bool
	CPUList         string
	KNICpuIdx       string
	Pcap            bool
	EnableDebugLog  bool
	EnableFlowDebug bool
	S1uPortIdx      uint16
	SgiPortIdx      uint16
	S1uIP           string
	SgiIP           string
	S1uDeviceName   string
	SgiDeviceName   string
}

var (
	//DpConfig dp configuration object
	DpConfig = Config{}

	//SgiMac ...
	SgiMac [common.EtherAddrLen]uint8
	//S1uMac ...
	S1uMac [common.EtherAddrLen]uint8

	//SDFUlL3Rules ...
	SDFUlL3Rules *packet.L3Rules
	//SDFDlL3Rules ...
	SDFDlL3Rules *packet.L3Rules
	//ADCL3Rules ...
	ADCL3Rules *packet.L3Rules

	//EnableStaticARP ...
	EnableStaticARP = false

	//UlMap ue context map contains UL information
	UlMap map[uint32]uint32
	//DlMap ue context map contains DL information
	DlMap map[uint32]*simucp.ENBFTEID
)

//initConfig
func initConfig() {

	flag.BoolVar(&DpConfig.NeedKNI, "kni", false, "need kni support")
	flag.BoolVar(&DpConfig.EnableDebugLog, "debug", false, "enable debug log")
	flag.BoolVar(&DpConfig.EnableFlowDebug, "flow_debug", false, "enable flow  debug log")
	s1uPort := flag.Uint("s1u_port", 0, "s1u port idx")
	sgiPort := flag.Uint("sgi_port", 1, "sgi port idx")
	flag.StringVar(&DpConfig.S1uIP, "s1u_ip", "", "s1u ip")
	flag.StringVar(&DpConfig.SgiIP, "sgi_ip", "", "sgi ip")
	flag.StringVar(&DpConfig.S1uDeviceName, "s1u_dev", "S1UDev", "kni device name for s1u")
	flag.StringVar(&DpConfig.SgiDeviceName, "sgi_dev", "SGIDev", "kni device name for sgi")
	flag.StringVar(&DpConfig.CPUList, "cpu_list", "", "cpu list")

	flag.Parse()

	DpConfig.S1uPortIdx = uint16(*s1uPort)
	DpConfig.SgiPortIdx = uint16(*sgiPort)

	fmt.Printf("[INFO] S1uPortIdx = %v , SgiPortIdx = %v  \n", DpConfig.S1uPortIdx, DpConfig.SgiPortIdx)
	fmt.Printf("[INFO] S1uIP = %v , SgiIP = %v  \n", DpConfig.S1uIP, DpConfig.SgiIP)
	fmt.Printf("[INFO] KNI = %v , CPU_LIST %s , kniCpuIdx = %v  \n", DpConfig.NeedKNI, DpConfig.CPUList, DpConfig.KNICpuIdx)
	fmt.Printf("[INFO] S1uDeviceName = %s , SgiDeviceName = %s \n", DpConfig.S1uDeviceName, DpConfig.SgiDeviceName)

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

// Start dp
func main() {

	//intialize config
	initConfig()

	//setup log level DP logging set to INFO
	FlowLogType := common.No
	if DpConfig.EnableDebugLog == true {
		FlowLogType = common.Info
	}
	if DpConfig.EnableFlowDebug == true {
		FlowLogType = common.Debug
	}
	common.SetLogType(FlowLogType)
	//intialize logger
	initLogger()
	//initialize rules
	rule.Init()

	// train DP
	UlMap, DlMap = simucp.TrainDP()

	if EnableStaticARP {
		sarp.Configure()
	} else {
		darp.Configure()
	}
	fmt.Println("******* DP configured successfully *******")
	//set the flow configuration
	flowConfig := flow.Config{

		NeedKNI: DpConfig.NeedKNI,
		CPUList: DpConfig.CPUList,
		LogType: FlowLogType,
	}

	//Initialize system
	flow.CheckFatal(flow.SystemInit(&flowConfig))
	S1uMac = flow.GetPortMACAddress(DpConfig.S1uPortIdx)
	SgiMac = flow.GetPortMACAddress(DpConfig.SgiPortIdx)

	common.PrintMAC("S1U port MAC : ", S1uMac)
	common.PrintMAC("SGI port MAC : ", SgiMac)

	var err1 error
	SDFUlL3Rules, err1 = packet.GetL3ACLFromORIG(rule.SdfUlACLFilePath)
	flow.CheckFatal(err1)
	SDFDlL3Rules, err1 = packet.GetL3ACLFromORIG(rule.SdfDlACLFilePath)
	flow.CheckFatal(err1)
	ADCL3Rules, err1 = packet.GetL3ACLFromORIG(rule.AdcACLFilePath)
	flow.CheckFatal(err1)

	if DpConfig.NeedKNI == true {
		// create KNI Tap
		s1uKniDev, err := flow.CreateKniDevice(DpConfig.S1uPortIdx, DpConfig.S1uDeviceName)
		flow.CheckFatal(err)
		sgiKniDev, err := flow.CreateKniDevice(DpConfig.SgiPortIdx, DpConfig.SgiDeviceName)
		flow.CheckFatal(err)

		//set receiver on S1U port
		s1uEthInFlow, _ := flow.SetReceiver(DpConfig.S1uPortIdx)
		//set receiver on SGi port
		sgiEthInFlow, _ := flow.SetReceiver(DpConfig.SgiPortIdx)

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

		//set sender on S1U
		flow.SetSender(s1uOutFlow, DpConfig.S1uPortIdx)
		//set sender on SGi
		flow.SetSender(sgiOutFlow, DpConfig.SgiPortIdx)

	} else {

		//set receiver on S1U port
		s1uEthInFlow, err := flow.SetReceiver(DpConfig.S1uPortIdx)
		flow.CheckFatal(err)
		//set receiver on SGi port
		sgiEthInFlow, err := flow.SetReceiver(DpConfig.SgiPortIdx)
		flow.CheckFatal(err)

		// Filter traffic
		flow.SetHandlerDrop(s1uEthInFlow, S1uFilter, nil)
		flow.SetHandlerDrop(sgiEthInFlow, SgiFilter, nil)

		//set sender on S1U
		flow.SetSender(sgiEthInFlow, DpConfig.S1uPortIdx)
		//set sender on SGi
		flow.SetSender(s1uEthInFlow, DpConfig.SgiPortIdx)

	}

	fmt.Println("******* DP started successfully *********")
	go PrintStats()

	flow.SystemStart()
} //

//DownlinkFilterKni ...
func DownlinkFilterKni(current *packet.Packet, context flow.UserContext) bool {
	atomic.AddUint64(&global.KniDlRxCounter, 1)
	ipv4, ipv6, arpPkt := current.ParseAllKnownL3()
	//	common.LogInfo(common.Info, "In SGI FilterFunction ", ipv4, arpPkt)
	if arpPkt != nil {
		if EnableStaticARP == false && arpPkt.Operation == 512 {
			common.LogInfo(common.Info, "ARP Response recv = ", arpPkt)
			darp.UpdateUlArpTable(arpPkt, DpConfig.SgiPortIdx, DpConfig.SgiDeviceName)
		}
		atomic.AddUint64(&global.KniDlTxCounter, 1)
		return true
	} else if ipv4 != nil {

		if ipv4.NextProtoID == common.ICMPNumber {
			common.LogInfo(common.Info, "PING pkt found ")
			atomic.AddUint64(&global.KniDlTxCounter, 1)
			return true
		}
	} else if ipv6 != nil {
		if ipv6.Proto == common.ICMPNumber {
			atomic.AddUint64(&global.KniDlTxCounter, 1)
			return true
		}
	}
	return false
}

// Apply ADC/SDF rules
func applyDlRulesFilter(current *packet.Packet) bool {

	sdfIdx := current.L3ACLPort(SDFDlL3Rules)
	adcIdx := current.L3ACLPort(ADCL3Rules)

	//	common.LogInfo(common.Info, "SDX Rule Idx  #", int(sdfIdx))
	//	common.LogInfo(common.Info, "ADC Rule Idx  #", int(adcIdx))

	pccFilter := rule.LookUpPCCRuleBySDF(int(sdfIdx))
	adcPCCFilter, err := rule.LookUpPCCRuleByADC(int(adcIdx))
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
	pkt.Ether.SAddr = S1uMac
	if EnableStaticARP == true {
		dmac, err := sarp.LookArpTable(ipv4.DstAddr, pkt)
		if err == nil {
			copy(pkt.Ether.DAddr[:], dmac)
			atomic.AddUint64(&global.DlTxCounter, 1)
		} else {
			return false
		}
	} else {
		dmac, sendArp, err := darp.LookupDlArpTable(ipv4.DstAddr, pkt) //s1uGwMac
		if err == nil {
			copy(pkt.Ether.DAddr[:], dmac)
			atomic.AddUint64(&global.DlTxCounter, 1)
		} else {
			if sendArp {
				packet.InitARPRequestPacket(pkt, S1uMac, common.StringToIPv4(DpConfig.S1uIP), ipv4.DstAddr)
				common.LogInfo(common.Info, "[DL] Sending ARP request", pkt)
			} else {
				return false
			}
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
		common.LogInfo(common.Info, "[DL]Not a valid Ipv4 PKT : INVALID PKT REJECT")
		return false
	}
	atomic.AddUint64(&global.DlRxCounter, 1)

	fteid, ok := DlMap[pktIpv4.DstAddr]

	if ok == false {
		common.LogError(common.Info, "[DL] INVALID PKT REJECT : TEID not found for UE_IP ", pktIpv4)
		return false
	}

	if applyDlRulesFilter(current) == false {
		return false
	}

	//    if config.DEBUG == true {
	//	common.LogInfo(common.Info, "encap:teid = ", common.SwapBytesUint32(fteid.ENB_TEID))
	//	common.LogInfo(common.Info, "encap:pkt ipv4 = ", pktIpv4)
	//    }

	if current.EncapsulateIPv4GTP(fteid.TEID) == false {
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

	ipv4.TotalLength = packet.SwapBytesUint16(uint16(length - common.EtherLen))
	ipv4.NextProtoID = common.UDPNumber

	ipv4.SrcAddr = common.StringToIPv4(DpConfig.S1uIP)
	ipv4.DstAddr = fteid.IP
	ipv4.HdrChecksum = packet.CalculateIPv4Checksum(ipv4)

	current.ParseL4ForIPv4()
	udp := current.GetUDPNoCheck()

	// construct udphdr
	udp.SrcPort = packet.SwapUDPPortGTPU
	udp.DstPort = packet.SwapUDPPortGTPU
	udp.DgramLen = uint16(length - common.EtherLen - common.IPv4MinLen)
	udp.DgramCksum = 0

	if updateDlNextHopInfo(current, context, ipv4) == false {
		return false
	}

	return true
}

//UplinkFilterKni ...
func UplinkFilterKni(current *packet.Packet, context flow.UserContext) bool {

	atomic.AddUint64(&global.KniUlTxCounter, 1)

	ipv4, ipv6, arpPkt := current.ParseAllKnownL3()
	//	common.LogInfo(common.Info, "In S1U FilterFunction ", ipv4, arpPkt)
	if arpPkt != nil {
		if EnableStaticARP == false && arpPkt.Operation == 512 {
			common.LogInfo(common.Info, "ARP response recv = ", arpPkt)
			darp.UpdateDlArpTable(arpPkt, DpConfig.S1uPortIdx, DpConfig.S1uDeviceName)
		}
		atomic.AddUint64(&global.KniUlTxCounter, 1)
		return true
	} else if ipv4 != nil {

		if ipv4.NextProtoID == common.ICMPNumber {
			common.LogInfo(common.Info, "PING pkt found ")
			atomic.AddUint64(&global.KniUlTxCounter, 1)
			return true
		}
	} else if ipv6 != nil {
		if ipv6.Proto == common.ICMPNumber {
			atomic.AddUint64(&global.KniUlTxCounter, 1)
			return true
		}
	}
	return false
} //

// Apply ADC/SDF rules
func applyUlRulesFilter(current *packet.Packet) bool {

	sdfIdx := current.L3ACLPort(SDFUlL3Rules)
	adcIdx := current.L3ACLPort(ADCL3Rules)
	//	common.LogInfo(common.Info, "SDX Rule Idx  #", int(sdf_idx))
	//	common.LogInfo(common.Info, "ADC Rule Idx  #", int(adc_idx))

	pccFilter := rule.LookUpPCCRuleBySDF(int(sdfIdx))
	adcPCCFilter, err := rule.LookUpPCCRuleByADC(int(adcIdx))
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
	pkt.Ether.SAddr = SgiMac

	if EnableStaticARP == true {
		//Lookup arp table
		dmac, err := sarp.LookArpTable(ipv4.DstAddr, pkt)
		if err == nil {
			copy(pkt.Ether.DAddr[:], dmac)
			atomic.AddUint64(&global.UlTxCounter, 1)
		} else {
			return false
		}
	} else {
		//Lookup arp table
		dmac, sendArp, err := darp.LookupUlArpTable(ipv4.DstAddr, pkt) //sgiGwMac

		if err == nil {
			copy(pkt.Ether.DAddr[:], dmac)
			atomic.AddUint64(&global.UlTxCounter, 1)
		} else {
			if sendArp {
				//sending arp request pkt only once
				packet.InitARPRequestPacket(pkt, SgiMac, common.StringToIPv4(DpConfig.SgiIP), ipv4.DstAddr)
				common.LogInfo(common.Info, "[UL] Sending ARP request", pkt)
			} else {
				return false
			}
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
	if ipv4 == nil || ipv4.DstAddr != common.StringToIPv4(DpConfig.S1uIP) {
		// reject with wrong dest ip
		common.LogError(common.Info, " [UL] reject dest ip doesn't match")
		if ipv4 != nil {
			common.LogError(common.Info, "[UL] reject dest ip doesn't match %v", ipv4)
		}
		return false
	}

	current.ParseL4ForIPv4()
	udp := current.GetUDPForIPv4()

	if udp == nil || udp.DstPort != packet.SwapUDPPortGTPU {
		// reject un-tunneled packet
		common.LogError(common.Info, "rejecting un-tunneled packet")
		return false
	}
	gtpu := current.GTPIPv4FastParsing()

	if gtpu.TEID == 0 || gtpu.MessageType != packet.G_PDU {
		// reject for gtpu reasons
		common.LogError(common.Info, "rejecting not valid GTPU packet")
		return false
	}
	atomic.AddUint64(&global.UlRxCounter, 1) //increment counters

	//make a copy of gtpu
	pktTEID := gtpu.TEID

	_, ok := UlMap[packet.SwapBytesUint32(pktTEID)]

	if ok == false {
		common.LogError(common.Info, "[UL] INVALID PKT REJECT :  UE_CONEXT not found for TEID", packet.SwapBytesUint32(pktTEID))
		return false
	}

	if current.DecapsulateIPv4GTP() == false {
		common.LogError(common.Info, "reject unable to decap GTPU header")
		return false
	}

	current.ParseL3()
	ipv4 = current.GetIPv4()

	//	common.LogInfo(common.Info, "decap:gtpu.TEID = ", common.SwapBytesUint32(pktTEID))
	//	common.LogInfo(common.Info, "decap:inner pkt src ipv4 = ", ipv4)
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
	fmt.Printf("\n\t\tUPLINK\t\t\t\t\t\t||\t\tDOWNLINK")
	count := 0
	for {
		if count%20 == 0 {
			fmt.Printf("\n%-11s %-11s %-11s %-11s %-11s|| %-11s %-11s %-11s%-11s %-11s\n", "KNI-RX", "KNI-TX", "UL-RX", "UL-TX", "UL-DFF", "KNI-RX", "KNI-TX", "DL-RX", "DL-TX", "DL-DFF")
		}
		fmt.Printf("%-11d %-11d %-11d %-11d %-11d|| %-11d %-11d %-11d%-11d %-11d\n", global.KniUlRxCounter, global.KniUlTxCounter, global.UlRxCounter, global.UlTxCounter, (global.UlRxCounter - global.UlTxCounter), global.KniDlRxCounter, global.KniDlTxCounter, global.DlRxCounter, global.DlTxCounter, (global.DlRxCounter - global.DlTxCounter))
		//  fmt.Printf("\r\x1b[32;1mPKT UL Tx/Rx : %d/%d  , PKT DL Tx/Rx : %d/%d\x1b[0m",ul_tx_pkt_counter,ul_rx_pkt_counter,dl_tx_pkt_counter,dl_rx_pkt_counter)
		time.Sleep(1000 * time.Millisecond)
		count++
	}
}
