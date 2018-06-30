package main

import (
	"flag"
	"fmt"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/ngic/arp"
	"github.com/intel-go/nff-go/ngic/rules"
	"github.com/intel-go/nff-go/ngic/simu_cp"
	"github.com/intel-go/nff-go/ngic/utils"
	"github.com/intel-go/nff-go/packet"
	"log"
	"os"
	"sync/atomic"
	"time"
)

//TODO PCAP support
var GEN_PCAP bool = false
var s1u_pcap_f *os.File = nil
var sgi_pcap_f *os.File = nil

var sgiMac [common.EtherAddrLen]uint8
var s1uMac [common.EtherAddrLen]uint8

var ul_map map[uint32]uint32
var dl_map map[uint32]*simu_cp.ENB_fteid

//
// DP Config structure
//
type DPConfig struct {
	NeedKNI       bool
	CPUList       string
	PCAP          bool
	DEBUG         bool
	FLOW_DEBUG    bool
	S1U_PORT_IDX  uint16
	SGI_PORT_IDX  uint16
	S1U_IP        string
	SGI_IP        string
	S1UDeviceName string
	SGIDeviceName string
}

var config DPConfig = DPConfig{}
var sdf_ul_l3Rules *packet.L3Rules
var sdf_dl_l3Rules *packet.L3Rules
var adc_l3Rules *packet.L3Rules

//
//Initialize configuration
func initConfig() {

	flag.BoolVar(&config.NeedKNI, "kni", false, "need kni support")
	flag.BoolVar(&config.DEBUG, "debug", false, "enable debug log")
	flag.BoolVar(&config.FLOW_DEBUG, "flow_debug", false, "enable flow  debug log")
	s1u_port := flag.Uint("s1u_port", 0, "s1u port idx")
	sgi_port := flag.Uint("sgi_port", 1, "sgi port idx")

	flag.StringVar(&config.S1U_IP, "s1u_ip", "", "s1u ip")
	flag.StringVar(&config.SGI_IP, "sgi_ip", "", "sgi ip")
	flag.StringVar(&config.S1UDeviceName, "s1u_dev", "S1UDev", "kni device name for s1u")
	flag.StringVar(&config.SGIDeviceName, "sgi_dev", "SGIDev", "kni device name for sgi")
	flag.StringVar(&config.CPUList, "cpu_list", "", "cpu list")

	flag.Parse()

	if config.CPUList == "" {
		flag.Usage()
		fmt.Println("use ./run.sh")
		os.Exit(1)
	}

	config.S1U_PORT_IDX = uint16(*s1u_port)
	config.SGI_PORT_IDX = uint16(*sgi_port)

	utils.SetLogType(utils.Info)
	if config.DEBUG == true {
		utils.SetLogType(utils.Debug)
	}

	fmt.Printf("[INFO] S1U_PORT_IDX = %v , SGI_PORT_IDX = %v  \n", config.S1U_PORT_IDX, config.SGI_PORT_IDX)
	fmt.Printf("[INFO] S1U_IP = %v , SGI_IP = %v  \n", config.S1U_IP, config.SGI_IP)
	fmt.Printf("[INFO] KNI = %v , CPU_LIST %s \n", config.NeedKNI, config.CPUList)
	fmt.Printf("[INFO] S1UDeviceName = %s , SGIDeviceName = %s \n", config.S1UDeviceName, config.SGIDeviceName)

	//Init rules
	rules.Init()

	//Populate UL and DL entries
	ul_map, dl_map = simu_cp.TrainDP()

	//populate arp table
	arp.ConfigureStaticArp(rules.STATIC_ARP_FILE_PATH)
	fmt.Println("******* DP configured successfully *******")
}

//
// Method :  init pcap
//
func initPCAP() {

	s1u_pcap_f, err := os.Create("s1u_int.pcap")
	if err != nil {
		log.Fatal(err)
	}

	sgi_pcap_f, err := os.Create("sgi_int.pcap")
	if err != nil {
		log.Fatal(err)
	}

	defer s1u_pcap_f.Close()

	err = packet.WritePcapGlobalHdr(s1u_pcap_f)
	if err != nil {
		log.Fatal(err)
	}

	defer sgi_pcap_f.Close()

	err = packet.WritePcapGlobalHdr(sgi_pcap_f)
	if err != nil {
		log.Fatal(err)
	}
}

//--------------------------------------------------------------
//  Main method
//--------------------------------------------------------------
func main() {

	//Initialize configuration
	initConfig()

	FlowLogType := common.No
	if config.FLOW_DEBUG == true {
		FlowLogType = common.Debug
	}

	//set the flow configuration
	flow_config := flow.Config{
		// Is required for KNI
		NeedKNI: config.NeedKNI,
		CPUList: config.CPUList,
		LogType: FlowLogType,
	}

	//Initialize system
	utils.CheckFatal(flow.SystemInit(&flow_config))
	s1uMac = flow.GetPortMACAddress(config.S1U_PORT_IDX)
	sgiMac = flow.GetPortMACAddress(config.SGI_PORT_IDX)

	utils.PrintMAC("S1U port MAC : ", s1uMac)
	utils.PrintMAC("SGI port MAC : ", sgiMac)

	var err error
	sdf_ul_l3Rules, err = packet.GetL3ACLFromORIG(rules.SDF_UL_ACL_FILE_PATH)
	utils.CheckFatal(err)
	sdf_dl_l3Rules, err = packet.GetL3ACLFromORIG(rules.SDF_DL_ACL_FILE_PATH)
	utils.CheckFatal(err)
	adc_l3Rules, err = packet.GetL3ACLFromORIG(rules.ADC_ACL_FILE_PATH)
	utils.CheckFatal(err)

	if config.NeedKNI == true {
		// create KNI Tap
		s1uKniDev, err := flow.CreateKniDevice(config.S1U_PORT_IDX, config.S1UDeviceName)
		utils.CheckFatal(err)
		sgiKniDev, err := flow.CreateKniDevice(config.SGI_PORT_IDX, config.SGIDeviceName)
		utils.CheckFatal(err)
		//set receiver on S1U port
		s1uEthInFlow, _ := flow.SetReceiver(config.S1U_PORT_IDX)
		//set receiver on SGi port
		sgiEthInFlow, _ := flow.SetReceiver(config.SGI_PORT_IDX)

		// set receiver on KNI Tap
		s1uKniInFlow := flow.SetReceiverKNI(s1uKniDev)
		sgiKniInFlow := flow.SetReceiverKNI(sgiKniDev)

		// Filter traffic
		toS1uKniFlow, err := flow.SetSeparator(s1uEthInFlow, s1u_handler, nil)
		toSgiKniFlow, err := flow.SetSeparator(sgiEthInFlow, sgi_handler, nil)

		flow.SetHandlerDrop(toS1uKniFlow, FilterFunction, nil)
		flow.SetHandlerDrop(toSgiKniFlow, FilterFunction, nil)

		//send invalid pkts > knidev
		utils.CheckFatal(flow.SetSenderKNI(toS1uKniFlow, s1uKniDev))
		utils.CheckFatal(flow.SetSenderKNI(toSgiKniFlow, sgiKniDev))

		// merge the flows
		s1uOutFlow, err := flow.SetMerger(sgiEthInFlow, s1uKniInFlow)
		utils.CheckFatal(err)
		sgiOutFlow, err := flow.SetMerger(s1uEthInFlow, sgiKniInFlow)
		utils.CheckFatal(err)

		//set sender on S1U
		flow.SetSender(s1uOutFlow, config.S1U_PORT_IDX)
		//set sender on SGi
		flow.SetSender(sgiOutFlow, config.SGI_PORT_IDX)

	} else {

		//set receiver on S1U port
		s1uEthInFlow, err := flow.SetReceiver(config.S1U_PORT_IDX)
		utils.CheckFatal(err)
		//set receiver on SGi port
		sgiEthInFlow, err := flow.SetReceiver(config.SGI_PORT_IDX)
		utils.CheckFatal(err)

		// Filter traffic
		flow.SetHandlerDrop(s1uEthInFlow, s1u_handler, nil)
		flow.SetHandlerDrop(sgiEthInFlow, sgi_handler, nil)

		//set sender on S1U
		flow.SetSender(sgiEthInFlow, config.S1U_PORT_IDX)
		//set sender on SGi
		flow.SetSender(s1uEthInFlow, config.SGI_PORT_IDX)

	}

	//------------------------------------------------------------------
	fmt.Println("******* DP started successfully *********")
	if flow_config.LogType == common.No {
		go printStats()
	}

	flow.SystemStart()

}

//
// Method : filter ARP/ICMP pkts reject other
//
func FilterFunction(current *packet.Packet, context flow.UserContext) bool {
	ipv4, ipv6, arp := current.ParseAllKnownL3()
	if arp != nil {
		utils.LogDebug(utils.Debug, "ARP pkt found ", ipv4.DstAddr)
		return true
	} else if ipv4 != nil {

		if ipv4.NextProtoID == common.ICMPNumber {
			utils.LogDebug(utils.Debug, "PING pkt found ")
			return true
		}
	} else if ipv6 != nil {
		if ipv6.Proto == common.ICMPNumber {
			return true
		}
	}
	return false
}

//
// Method : Filter UL traffic
// Apply ADC/SDF rules
//
func filter_ul_traffic(current *packet.Packet) bool {

	sdf_idx := current.L3ACLPort(sdf_ul_l3Rules)
	adc_idx := current.L3ACLPort(adc_l3Rules)
	utils.LogDebug(utils.Debug, "SDX Rule Idx  #", int(sdf_idx))
	utils.LogDebug(utils.Debug, "ADC Rule Idx  #", int(adc_idx))

	pcc_filter := rules.LookUpPCCRuleBySDF(int(sdf_idx))
	adc_pcc_filter, err := rules.LookUpPCCRuleByADC(int(adc_idx))
	if err == nil {
		if pcc_filter.PRECEDENCE > adc_pcc_filter.PRECEDENCE {
			pcc_filter = adc_pcc_filter
		}
	}
	//sort in ascending order
	gate_status := pcc_filter.GATE_STATUS

	if gate_status == 0 { //drop
		ipv4 := current.GetIPv4()
		utils.LogError(utils.Debug, "DROPING PKT ", ipv4)
		return false
	}

	return true
}

//
// Method : Filter DL traffic
// Apply ADC/SDF rules
//
func filter_dl_traffic(current *packet.Packet) bool {

	sdf_idx := current.L3ACLPort(sdf_dl_l3Rules)
	adc_idx := current.L3ACLPort(adc_l3Rules)

	utils.LogDebug(utils.Debug, "SDX Rule Idx  #", int(sdf_idx))
	utils.LogDebug(utils.Debug, "ADC Rule Idx  #", int(adc_idx))

	pcc_filter := rules.LookUpPCCRuleBySDF(int(sdf_idx))
	adc_pcc_filter, err := rules.LookUpPCCRuleByADC(int(adc_idx))
	if err == nil {
		if pcc_filter.PRECEDENCE > adc_pcc_filter.PRECEDENCE {
			pcc_filter = adc_pcc_filter
		}
	}
	//sort in ascending order
	gate_status := pcc_filter.GATE_STATUS

	if gate_status == 0 {
		ipv4 := current.GetIPv4()
		utils.LogError(utils.Debug, "DROPING PKT ", ipv4)
		return false
	}

	return true
}

//
// Updated packet's next hop info
//
func update_nexthop_info_ul(pkt *packet.Packet, ctx flow.UserContext, ipv4 *packet.IPv4Hdr) bool {
	// ARP lookup for S1U_GW_IP
	pkt.Ether.SAddr = sgiMac

	dmac, err := arp.LookArpTable(ipv4.DstAddr, pkt) //sgiGwMac
	if err == nil {
		pkt.Ether.DAddr = dmac
	} else {
		return false
	}
	return true

}

//
// Updated packet's next hop info
//
func update_nexthop_info_dl(pkt *packet.Packet, ctx flow.UserContext, ipv4 *packet.IPv4Hdr) bool {

	// ARP lookup for SGI_GW_IP
	pkt.Ether.SAddr = s1uMac
	dmac, err := arp.LookArpTable(ipv4.DstAddr, pkt) //s1uGwMac
	if err == nil {
		pkt.Ether.DAddr = dmac
	} else {
		return false
	}

	return true
}

//
// Method : Decap packet
//          Check if it's valid GTPU packet otherwise drop it
//
func s1u_handler(current *packet.Packet, context flow.UserContext) bool {
	atomic.AddUint64(&ul_rx_pkt_cnt, 1)

	current.ParseL3()
	ipv4 := current.GetIPv4()
	if ipv4 == nil || ipv4.DstAddr != utils.StringToIPv4(config.S1U_IP) {
		// reject with wrong dest ip
		utils.LogError(utils.Debug, "INVALID PKT REJECT: dest ip doesn't match")
		if ipv4 != nil {
			utils.LogError(utils.Debug, "INVALID PKT REJECT: dest ip doesn't match %v", ipv4)
		}
		return false
	}

	current.ParseL4ForIPv4()
	udp := current.GetUDPForIPv4()

	if udp == nil || udp.DstPort != packet.SwapUDPPortGTPU {
		// reject un-tunneled packet
		utils.LogError(utils.Debug, "INVALID PKT REJECT: un-tunneled packet")
		return false
	}
	gtpu := current.GTPIPv4FastParsing()

	if gtpu.TEID == 0 || gtpu.MessageType != packet.G_PDU {
		// reject for gtpu reasons
		utils.LogError(utils.Debug, "INVALID PKT REJECT not valid GTPU packet")
		return false
	}

	//make a copy of gtpu
	pkt_gtpu_teid := gtpu.TEID
	// TODO
	// Look up gtpu.TEID sesson and UE IP validate against session
	//
	_, ok := ul_map[utils.SwapBytesUint32(pkt_gtpu_teid)]

	if ok == false {
		utils.LogError(utils.Debug, "INVALID PKT REJECT :  UE_CONEXT not found for TEID", utils.SwapBytesUint32(pkt_gtpu_teid))
		return false
	}

	if current.DecapsulateIPv4GTP() == false {
		utils.LogError(utils.Debug, "INVALID PKT REJECT: unable to decap GTPU header")
		return false
	}

	current.ParseL3()
	ipv4 = current.GetIPv4()

//	utils.LogDebug(utils.Debug, "decap:gtpu.TEID = ", utils.SwapBytesUint32(pkt_gtpu_teid))
//	utils.LogDebug(utils.Debug, "decap:inner pkt src ipv4 = ", ipv4)

	if filter_ul_traffic(current) == false {
		return false
	}

	if update_nexthop_info_ul(current, context, ipv4) == false {
		return false
	}

	atomic.AddUint64(&ul_tx_pkt_cnt, 1)
	return true
}

//
// Method : encapsulate the ipv4 packet to GTPU pkt
//

func sgi_handler(current *packet.Packet, context flow.UserContext) bool {
	atomic.AddUint64(&dl_rx_pkt_cnt, 1)
	current.ParseL3()

	if filter_dl_traffic(current) == false {
		return false
	}

	//check if valid pkt
	pkt_ipv4 := current.GetIPv4()
	fteid, ok := dl_map[pkt_ipv4.DstAddr]

	if ok == false {
		utils.LogError(utils.Debug, "INVALID PKT REJECT: TEID not found for UE_IP ", utils.Int2ip(pkt_ipv4.DstAddr).String())
		return false
	}

//	utils.LogDebug(utils.Debug, "encap:teid = ", utils.SwapBytesUint32(fteid.ENB_TEID))
//	utils.LogDebug(utils.Debug, "encap:pkt ipv4 = ", pkt_ipv4)

	if current.EncapsulateIPv4GTP(fteid.ENB_TEID) == false {
		utils.LogError(utils.Debug, "INVALID PKT REJECT: Encapsulating GTP pkt ")
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

	ipv4.SrcAddr = utils.StringToIPv4(config.S1U_IP)
	ipv4.DstAddr = fteid.ENB_IP
	ipv4.HdrChecksum = packet.CalculateIPv4Checksum(ipv4)

	current.ParseL4ForIPv4()
	udp := current.GetUDPNoCheck()

	// construct udphdr
	udp.SrcPort = packet.SwapUDPPortGTPU
	udp.DstPort = packet.SwapUDPPortGTPU
	udp.DgramLen = uint16(length - common.EtherLen - common.IPv4MinLen)
	udp.DgramCksum = 0

	if update_nexthop_info_dl(current, context, ipv4) == false {
		return false
	}

	atomic.AddUint64(&dl_tx_pkt_cnt, 1)
	return true
}

// counters
var ul_rx_pkt_cnt uint64 = 0
var dl_rx_pkt_cnt uint64 = 0
var ul_tx_pkt_cnt uint64 = 0
var dl_tx_pkt_cnt uint64 = 0

//
// Method : print ul/dl rx/tx stats every second
//
func printStats() {
	fmt.Printf("\n\t\tUPLINK\t\t\t\t\t||\t\tDOWNLINK")
	count := 0
	for {
		if count%20 == 0 {
			fmt.Printf("\n\t%-11s\t%-11s\t%-11s\t||\t%-11s\t%-11s\t%-11s\n", "UL-RX", "UL-TX", "UL-DFF", "DL-RX", "DL-TX", "DL-DFF")
		}
		fmt.Printf("\t%-11d\t%-11d\t%-11d\t||\t%-11d\t%-11d\t%-11d\n", ul_rx_pkt_cnt, ul_tx_pkt_cnt, (ul_rx_pkt_cnt - ul_tx_pkt_cnt), dl_rx_pkt_cnt, dl_tx_pkt_cnt, (dl_rx_pkt_cnt - dl_tx_pkt_cnt))
		//  fmt.Printf("\r\x1b[32;1mPKT UL Tx/Rx : %d/%d  , PKT DL Tx/Rx : %d/%d\x1b[0m",ul_tx_pkt_counter,ul_rx_pkt_counter,dl_tx_pkt_counter,dl_rx_pkt_counter)
		time.Sleep(1000 * time.Millisecond)
		count++
	}
}
