// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/test/localTesting/pktgen/parseConfig"
)

var (
	count         uint64
	testDoneEvent *sync.Cond
	number        uint64
	isCycled      bool
)

type mapFlags struct {
	value map[int]string
	set   bool
}

func (m *mapFlags) String() string {
	s := ""
	for key, value := range (*m).value {
		if s != "" {
			s += ","
		}
		s += fmt.Sprintf("%d: '%s'", key, value)
	}
	return s
}

func (m *mapFlags) Set(s string) error {
	ss := strings.Split(s, ",")
	(*m).value = make(map[int]string)
	for _, val := range ss {
		val = strings.TrimSpace(val)
		pair := strings.Split(val, ":")
		key, err := strconv.Atoi(pair[0])
		if err != nil {
			return err
		}
		value := strings.Trim(pair[1], "' ")
		(*m).value[key] = value
	}
	(*m).set = true
	return nil
}

func main() {
	var (
		portflag           uint
		outFile, inFile    string
		outPort            uint16
		usePort, useFile   bool
		speed              uint64
		m                  sync.Mutex
		fileFlow, portFlow *flow.Flow
		eachPortConfig     mapFlags
	)
	flag.StringVar(&outFile, "outfile", "", "file to write output to")
	flag.UintVar(&portflag, "outport", 70000, "port to send output to")
	flag.StringVar(&inFile, "infile", "config.json", "file with configurations for generator")
	flag.Uint64Var(&number, "number", 10000000, "stop after generation number number")
	flag.BoolVar(&isCycled, "cycle", false, "cycle execution and generate infinite number of packets")
	flag.Uint64Var(&speed, "speed", 6000000, "speed of fast generator, Pkts/s")
	flag.Var(&eachPortConfig, "portConfig", "specify config per port portNum: 'path', portNum2: 'path2'. For example: 1: 'ip4.json', 0: 'mix.json'")
	flag.Parse()

	// Init NFF-GO system at 16 available cores
	config := flow.Config{}
	flow.CheckFatal(flow.SystemInit(&config))

	testDoneEvent = sync.NewCond(&m)

	if eachPortConfig.set {
		for key, value := range eachPortConfig.value {
			configuration, err := ReadConfig(value)
			if err != nil {
				panic(fmt.Sprintf("%s config reading failed: %v", value, err))
			}
			context, err := getGeneratorContext(configuration)
			flow.CheckFatal(err)
			outFlow, err := flow.SetFastGenerator(generate, speed, &context)
			flow.CheckFatal(err)
			flow.CheckFatal(flow.SetSender(outFlow, uint16(key)))
		}
	} else {
		if portflag != 70000 {
			usePort = true
			outPort = uint16(portflag)
		}
		if outFile != "" {
			useFile = true
		}
		if !usePort && !useFile {
			useFile = true
			outFile = "pkts_generated.pcap"
		}
		configuration, err := ReadConfig(inFile)
		if err != nil {
			panic(fmt.Sprintf("config reading failed: %v", err))
		}

		context, err := getGeneratorContext(configuration)
		flow.CheckFatal(err)
		fileFlow, err = flow.SetFastGenerator(generate, speed, &context)
		flow.CheckFatal(err)
		if useFile && usePort {
			portFlow, err = flow.SetCopier(fileFlow)
			flow.CheckFatal(err)
		} else {
			if usePort {
				portFlow = fileFlow
			}
		}
		if useFile {
			flow.CheckFatal(flow.SetSenderFile(fileFlow, outFile))
		}
		if usePort {
			flow.CheckFatal(flow.SetSender(portFlow, outPort))
		}
	}

	// Start pipeline
	go func() {
		flow.CheckFatal(flow.SystemStart())
	}()

	// Wait for enough packets to arrive
	testDoneEvent.L.Lock()
	testDoneEvent.Wait()
	testDoneEvent.L.Unlock()

	// Print report
	println("Sent", atomic.LoadUint64(&count), "packets")
}

// ReadConfig function reads and parses config file.
func ReadConfig(fileName string) ([]*parseConfig.MixConfig, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("opening file failed with: %v ", err)
	}
	cfg, err := parseConfig.ParseConfig(f)
	if err != nil {
		return nil, fmt.Errorf("parsing config failed with: %v", err)
	}
	return cfg, nil
}

func getNextAddr(addr *parseConfig.AddrRange) []uint8 {
	if len(addr.Current) == 0 {
		addr.Current = []uint8{0}
	}
	if addr.Incr == 0 {
		return addr.Current
	}
	// if current < min or current > max, copy min to current
	if bytes.Compare(addr.Current, addr.Min) < 0 || bytes.Compare(addr.Current, addr.Max) > 0 {
		addr.Current = make([]byte, len(addr.Min))
		copy(addr.Current, addr.Min)
	}
	// copy current to return
	retAddr := make([]byte, len(addr.Current))
	copy(retAddr, addr.Current)
	// increment current
	addressInt := big.NewInt(0)
	addressInt.SetBytes(addr.Current)
	addressInt.Add(big.NewInt(int64(addr.Incr)), addressInt)
	newAddr := addressInt.Bytes()
	copyAddr(addr.Current, newAddr, len(addr.Current))
	return retAddr
}

func copyAddr(destination []uint8, source []uint8, size int) {
	if size < len(source) {
		copy(destination[:], source[len(source)-size:])
	} else {
		copy(destination[size-len(source):], source[:])
	}
}

func getNextPort(port *parseConfig.PortRange) (nextPort uint16) {
	if len(port.Current) == 0 {
		port.Current = []uint16{0}
	}
	if port.Current[0] < port.Min || port.Current[0] > port.Max {
		port.Current[0] = port.Min
	}
	nextPort = port.Current[0]
	port.Current[0] += port.Incr
	return nextPort
}

func getNextSeqNumber(seq *parseConfig.Sequence) (nextSeqNum uint32) {
	if len(seq.Next) == 0 {
		return 0
	}
	nextSeqNum = seq.Next[0]
	if seq.Type == parseConfig.RANDOM {
		seq.Next[0] = rand.Uint32()
	} else if seq.Type == parseConfig.INCREASING {
		seq.Next[0]++
	}
	return nextSeqNum
}

func generateData(configuration interface{}) ([]uint8, error) {
	switch data := configuration.(type) {
	case parseConfig.Raw:
		pktData := make([]uint8, len(data.Data))
		copy(pktData[:], ([]uint8(data.Data)))
		return pktData, nil
	case parseConfig.RandBytes:
		maxZise := data.Size + data.Deviation
		minSize := data.Size - data.Deviation
		randSize := uint(rand.Float64()*float64(maxZise-minSize) + float64(minSize))
		pktData := make([]uint8, randSize)
		for i := range pktData {
			pktData[i] = byte(rand.Int())
		}
		return pktData, nil
	case []parseConfig.PDistEntry:
		prob := 0.0
		rndN := math.Abs(rand.Float64())
		maxProb := parseConfig.PDistEntry{Probability: 0}
		for _, item := range data {
			prob += item.Probability
			if rndN <= prob {
				pktData, err := generateData(item.Data)
				if err != nil {
					return nil, fmt.Errorf("failed to fill data with pdist data type: %v", err)
				}
				return pktData, nil
			}
			if item.Probability > maxProb.Probability {
				maxProb = item
			}
		}
		if prob <= 0 || prob > 1 {
			return nil, fmt.Errorf("sum of pdist probabilities is invalid, %f", prob)
		}
		// get the variant with max prob
		// if something went wrong and rand did not match any prob
		// may happen if sum of prob was not 1
		pktData, err := generateData(maxProb.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to fill data with pdist data type: %v", err)
		}
		return pktData, nil
	}
	return nil, fmt.Errorf("unknown data type")
}

func getGenerator(configuration *parseConfig.PacketConfig) (func(*packet.Packet, *parseConfig.PacketConfig), error) {
	switch l2 := (configuration.Data).(type) {
	case parseConfig.EtherConfig:
		switch l3 := l2.Data.(type) {
		case parseConfig.IPConfig:
			switch l3.Data.(type) {
			case parseConfig.TCPConfig:
				return generateTCPIP, nil
			case parseConfig.UDPConfig:
				return generateUDPIP, nil
			case parseConfig.ICMPConfig:
				return generateICMPIP, nil
			case parseConfig.Raw, parseConfig.RandBytes, []parseConfig.PDistEntry:
				return generateIP, nil
			default:
				return nil, fmt.Errorf("unknown packet l4 configuration")
			}
		case parseConfig.ARPConfig:
			return generateARP, nil
		case parseConfig.Raw, parseConfig.RandBytes, []parseConfig.PDistEntry:
			return generateEther, nil
		default:
			return nil, fmt.Errorf("unknown packet l3 configuration")
		}
	default:
		return nil, fmt.Errorf("unknown packet l2 configuration")
	}
}

func checkFinish() {
	if isCycled {
		return
	}
	if atomic.AddUint64(&count, 1) >= number {
		time.Sleep(time.Second)
		testDoneEvent.Signal()
	}
}

// one unit for each mix
type generatorTableUnit struct {
	have, need    uint32
	generatorFunc func(*packet.Packet, *parseConfig.PacketConfig)
	config        *parseConfig.PacketConfig
}

func (gtu *generatorTableUnit) String() string {
	return fmt.Sprintf("need: %d, config: %v\n", gtu.need, gtu.config)
}

type genParameters struct {
	table  []generatorTableUnit
	next   []uint32
	length uint32
}

func (gp *genParameters) String() string {
	s := "genP:\n"
	for _, tu := range gp.table {
		s = s + fmt.Sprintf("\ttu: %v\n", tu.String())
	}
	s = s + fmt.Sprintf("next: %d, len: %d\n", gp.next, gp.length)
	return s
}

func (gp genParameters) Copy() interface{} {
	cpy := make([]generatorTableUnit, len(gp.table))
	copy(cpy, gp.table)
	return genParameters{table: cpy, next: []uint32{0}, length: gp.length}
}

func (gp genParameters) Delete() {
}

func getGeneratorContext(mixConfig []*parseConfig.MixConfig) (genParameters, error) {
	var t []generatorTableUnit
	for _, packetConfig := range mixConfig {
		genFunc, err := getGenerator(packetConfig.Config)
		if err != nil {
			return genParameters{}, err
		}
		tu := generatorTableUnit{have: 0, need: packetConfig.Quantity, generatorFunc: genFunc, config: packetConfig.Config}
		t = append(t, tu)
	}
	return genParameters{table: t, next: []uint32{0}, length: uint32(len(t))}, nil
}

func generate(pkt *packet.Packet, context flow.UserContext) {
	genP := context.(genParameters)
	table := genP.table
	next := genP.next[0]
	if genP.length > 1 {
		if table[next].have == table[next].need {
			context.(genParameters).table[next].have = 0
			if next+1 < genP.length {
				next++
			} else {
				next = 0
			}
			context.(genParameters).next[0] = next
		}
	}
	table[next].generatorFunc(pkt, table[next].config)
	context.(genParameters).table[next].have++
}

func generateEther(pkt *packet.Packet, config *parseConfig.PacketConfig) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	l2 := config.Data.(parseConfig.EtherConfig)
	data, err := generateData(l2.Data)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse data for l2: %v", err))
	}
	if data == nil {
		panic(fmt.Sprintf("failed to generate data"))
	}
	size := uint(len(data))
	if !packet.InitEmptyPacket(pkt, size) {
		panic(fmt.Sprintf("InitEmptyPacket failed"))
	}
	copy((*[1 << 30]uint8)(pkt.Data)[0:size], data)
	if err := fillEtherHdr(pkt, &l2); err != nil {
		panic(fmt.Sprintf("failed to fill ether header %v", err))
	}
	config.Data = l2
}

func generateIP(pkt *packet.Packet, config *parseConfig.PacketConfig) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	l2 := config.Data.(parseConfig.EtherConfig)
	l3 := l2.Data.(parseConfig.IPConfig)
	data, err := generateData(l3.Data)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse data for l3: %v", err))
	}
	if data == nil {
		panic(fmt.Sprintf("failed to generate data"))
	}
	size := uint(len(data))
	if l3.Version == 4 {
		if !packet.InitEmptyIPv4Packet(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv4Packet returned false"))
		}
	} else if l3.Version == 6 {
		if !packet.InitEmptyIPv6Packet(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv6Packet returned false"))
		}
	} else {
		panic(fmt.Sprintf("fillPacketl3 failed, unknovn version %d", l3.Version))
	}
	copy((*[1 << 30]uint8)(pkt.Data)[0:size], data)
	if err := fillIPHdr(pkt, &l3); err != nil {
		panic(fmt.Sprintf("failed to fill ip header %v", err))
	}
	if err := fillEtherHdr(pkt, &l2); err != nil {
		panic(fmt.Sprintf("failed to fill ether header %v", err))
	}
	if l3.Version == 4 {
		pkt.GetIPv4CheckVLAN().HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4CheckVLAN()))
	}
	l2.Data = l3
	config.Data = l2
}

func generateARP(pkt *packet.Packet, config *parseConfig.PacketConfig) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	l2 := config.Data.(parseConfig.EtherConfig)
	l3 := l2.Data.(parseConfig.ARPConfig)
	var SHA, THA [common.EtherAddrLen]uint8
	copyAddr(SHA[:], getNextAddr(&(l3.SHA)), common.EtherAddrLen)
	SPA := binary.LittleEndian.Uint32(net.IP(getNextAddr(&(l3.SPA))).To4())
	switch l3.Operation {
	case packet.ARPRequest:
		if l3.Gratuitous {
			if !packet.InitGARPAnnouncementRequestPacket(pkt, SHA, SPA) {
				panic(fmt.Sprintf("InitGARPAnnouncementRequestPacket returned false"))
			}
		} else {
			TPA := binary.LittleEndian.Uint32(net.IP(getNextAddr(&(l3.TPA))).To4())
			if !packet.InitARPRequestPacket(pkt, SHA, SPA, TPA) {
				panic(fmt.Sprintf("InitARPRequestPacket returned false"))
			}
		}
	case packet.ARPReply:
		if l3.Gratuitous {
			if !packet.InitGARPAnnouncementReplyPacket(pkt, SHA, SPA) {
				panic(fmt.Sprintf("InitGARPAnnouncementReplyPacket returned false"))
			}
		} else {
			copyAddr(THA[:], getNextAddr(&(l3.THA)), common.EtherAddrLen)
			TPA := binary.LittleEndian.Uint32(net.IP(getNextAddr(&(l3.TPA))).To4())
			if !packet.InitARPReplyPacket(pkt, SHA, THA, SPA, TPA) {
				panic(fmt.Sprintf("InitARPReplyPacket returned false"))
			}
		}
	default:
		panic(fmt.Sprintf("unsupported operation code: %d", l3.Operation))
	}
	if len(l2.DAddr.Current) != 0 {
		copyAddr(pkt.Ether.DAddr[:], getNextAddr(&(l2.DAddr)), common.EtherAddrLen)
	}
	if l2.VLAN != nil {
		if !pkt.AddVLANTag(l2.VLAN.TCI) {
			panic("failed to add vlan tag to arp packet")
		}
	}
	l2.Data = l3
	config.Data = l2
}

func generateTCPIP(pkt *packet.Packet, config *parseConfig.PacketConfig) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	l2 := config.Data.(parseConfig.EtherConfig)
	l3 := l2.Data.(parseConfig.IPConfig)
	l4 := l3.Data.(parseConfig.TCPConfig)
	data, err := generateData(l4.Data)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse data for l4: %v", err))
	}
	if data == nil {
		panic(fmt.Sprintf("failed to generate data"))
	}
	size := uint(len(data))
	if l3.Version == 4 {
		if !packet.InitEmptyIPv4TCPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv4TCPPacket returned false"))
		}
	} else if l3.Version == 6 {
		if !packet.InitEmptyIPv6TCPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv6TCPPacket returned false"))
		}
	} else {
		panic(fmt.Sprintf("fill packet l4 failed, unknovn version %d", l3.Version))
	}
	copy((*[1 << 30]uint8)(pkt.Data)[0:size], data)
	if err := fillTCPHdr(pkt, &l4); err != nil {
		panic(fmt.Sprintf("failed to fill tcp header %v", err))
	}
	if err := fillIPHdr(pkt, &l3); err != nil {
		panic(fmt.Sprintf("failed to fill ip header %v", err))
	}
	if err := fillEtherHdr(pkt, &l2); err != nil {
		panic(fmt.Sprintf("failed to fill ether header %v", err))
	}
	if l3.Version == 4 {
		pkt.GetIPv4CheckVLAN().HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4CheckVLAN()))
		pkt.GetTCPForIPv4().Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(pkt.GetIPv4CheckVLAN(), pkt.GetTCPForIPv4(), pkt.Data))
	} else if l3.Version == 6 {
		pkt.GetTCPForIPv6().Cksum = packet.SwapBytesUint16(packet.CalculateIPv6TCPChecksum(pkt.GetIPv6CheckVLAN(), pkt.GetTCPForIPv6(), pkt.Data))
	}
	l3.Data = l4
	l2.Data = l3
	config.Data = l2
}

func generateUDPIP(pkt *packet.Packet, config *parseConfig.PacketConfig) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	l2 := config.Data.(parseConfig.EtherConfig)
	l3 := l2.Data.(parseConfig.IPConfig)
	l4 := l3.Data.(parseConfig.UDPConfig)
	data, err := generateData(l4.Data)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse data for l4: %v", err))
	}
	if data == nil {
		panic(fmt.Sprintf("failed to generate data"))
	}
	size := uint(len(data))
	if l3.Version == 4 {
		if !packet.InitEmptyIPv4UDPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv4UDPPacket returned false"))
		}
	} else if l3.Version == 6 {
		if !packet.InitEmptyIPv6UDPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv6UDPPacket returned false"))
		}
	} else {
		panic(fmt.Sprintf("fill packet l4 failed, unknovn version %d", l3.Version))
	}
	copy((*[1 << 30]uint8)(pkt.Data)[0:size], data)
	if err := fillUDPHdr(pkt, &l4); err != nil {
		panic(fmt.Sprintf("failed to fill udp header %v", err))
	}
	if err := fillIPHdr(pkt, &l3); err != nil {
		panic(fmt.Sprintf("failed to fill ip header %v", err))
	}
	if err := fillEtherHdr(pkt, &l2); err != nil {
		panic(fmt.Sprintf("failed to fill ether header %v", err))
	}
	if l3.Version == 4 {
		pkt.GetIPv4CheckVLAN().HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4CheckVLAN()))
		pkt.GetUDPForIPv4().DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pkt.GetIPv4CheckVLAN(), pkt.GetUDPForIPv4(), pkt.Data))
	} else if l3.Version == 6 {
		pkt.GetUDPForIPv6().DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv6UDPChecksum(pkt.GetIPv6CheckVLAN(), pkt.GetUDPForIPv6(), pkt.Data))
	}
	l3.Data = l4
	l2.Data = l3
	config.Data = l2
}

func generateICMPIP(pkt *packet.Packet, config *parseConfig.PacketConfig) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	checkFinish()
	l2 := config.Data.(parseConfig.EtherConfig)
	l3 := l2.Data.(parseConfig.IPConfig)
	l4 := l3.Data.(parseConfig.ICMPConfig)
	data, err := generateData(l4.Data)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse data for l4: %v", err))
	}
	if data == nil {
		panic(fmt.Sprintf("failed to generate data"))
	}
	size := uint(len(data))
	if l3.Version == 4 {
		if !packet.InitEmptyIPv4ICMPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv4ICMPPacket returned false"))
		}
	} else if l3.Version == 6 {
		if !packet.InitEmptyIPv6ICMPPacket(pkt, size) {
			panic(fmt.Sprintf("InitEmptyIPv6ICMPPacket returned false"))
		}
	} else {
		panic(fmt.Sprintf("fill packet l4 failed, unknovn version %d", l3.Version))
	}
	copy((*[1 << 30]uint8)(pkt.Data)[0:size], data)
	if err := fillICMPHdr(pkt, &l4); err != nil {
		panic(fmt.Sprintf("failed to fill icmp header %v", err))
	}
	if err := fillIPHdr(pkt, &l3); err != nil {
		panic(fmt.Sprintf("failed to fill ip header %v", err))
	}
	if err := fillEtherHdr(pkt, &l2); err != nil {
		panic(fmt.Sprintf("failed to fill ether header %v", err))
	}
	if l3.Version == 4 {
		pkt.GetIPv4CheckVLAN().HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4CheckVLAN()))
		pkt.GetICMPForIPv4().Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(pkt.GetIPv4CheckVLAN(), pkt.GetICMPForIPv4(), pkt.Data))
	} else if l3.Version == 6 {
		pkt.GetICMPForIPv6().Cksum = packet.SwapBytesUint16(packet.CalculateIPv6ICMPChecksum(pkt.GetIPv6CheckVLAN(), pkt.GetICMPForIPv6(), pkt.Data))
	}
	l3.Data = l4
	l2.Data = l3
	config.Data = l2
}

func fillTCPHdr(pkt *packet.Packet, l4 *parseConfig.TCPConfig) error {
	emptyPacketTCP := (*packet.TCPHdr)(pkt.L4)
	emptyPacketTCP.SrcPort = packet.SwapBytesUint16(getNextPort(&(l4.SPort)))
	emptyPacketTCP.DstPort = packet.SwapBytesUint16(getNextPort(&(l4.DPort)))
	emptyPacketTCP.SentSeq = packet.SwapBytesUint32(getNextSeqNumber((&l4.Seq)))
	emptyPacketTCP.TCPFlags = l4.Flags
	return nil
}

func fillUDPHdr(pkt *packet.Packet, l4 *parseConfig.UDPConfig) error {
	emptyPacketUDP := (*packet.UDPHdr)(pkt.L4)
	emptyPacketUDP.SrcPort = packet.SwapBytesUint16(getNextPort(&(l4.SPort)))
	emptyPacketUDP.DstPort = packet.SwapBytesUint16(getNextPort(&(l4.DPort)))
	return nil
}

func fillICMPHdr(pkt *packet.Packet, l4 *parseConfig.ICMPConfig) error {
	emptyPacketICMP := (*packet.ICMPHdr)(pkt.L4)
	emptyPacketICMP.Type = l4.Type
	emptyPacketICMP.Code = l4.Code
	emptyPacketICMP.Identifier = l4.Identifier
	emptyPacketICMP.SeqNum = packet.SwapBytesUint16(uint16(getNextSeqNumber(&(l4.Seq))))
	return nil
}

func fillIPHdr(pkt *packet.Packet, l3 *parseConfig.IPConfig) error {
	if l3.Version == 4 {
		pktIP := pkt.GetIPv4()
		pktIP.SrcAddr = binary.LittleEndian.Uint32(net.IP(getNextAddr(&(l3.SAddr))).To4())
		pktIP.DstAddr = binary.LittleEndian.Uint32(net.IP(getNextAddr(&(l3.DAddr))).To4())
		return nil
	}
	pktIP := pkt.GetIPv6()
	nextAddr := getNextAddr(&(l3.SAddr))
	copyAddr(pktIP.SrcAddr[:], nextAddr, common.IPv6AddrLen)
	nextAddr = getNextAddr(&(l3.DAddr))
	copyAddr(pktIP.DstAddr[:], nextAddr, common.IPv6AddrLen)
	return nil
}

func fillEtherHdr(pkt *packet.Packet, l2 *parseConfig.EtherConfig) error {
	if l2.VLAN != nil {
		if err := addVLAN(pkt, l2.VLAN.TCI); err != nil {
			return err
		}
	}
	nextAddr := getNextAddr(&(l2.DAddr))
	copyAddr(pkt.Ether.DAddr[:], nextAddr, common.EtherAddrLen)
	nextAddr = getNextAddr(&(l2.SAddr))
	copyAddr(pkt.Ether.SAddr[:], nextAddr, common.EtherAddrLen)
	return nil
}

// faster version of packet.AddVLANTag, can be used only
// when ether src and dst are not set, but ether type is
// (most InitEmptyPacket functions do so).
func addVLAN(pkt *packet.Packet, tag uint16) error {
	if !pkt.EncapsulateHead(0, 4) {
		return fmt.Errorf("failed to add vlan tag, EncapsulateHead returned false")
	}
	pkt.Ether.EtherType = packet.SwapBytesUint16(common.VLANNumber)
	vhdr := pkt.GetVLAN()
	if vhdr == nil {
		return fmt.Errorf("failed to get vlan, GetVLAN returned nil")
	}
	vhdr.TCI = packet.SwapBytesUint16(tag)
	return nil
}
