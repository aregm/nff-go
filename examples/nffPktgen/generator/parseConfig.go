// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package generator

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/intel-go/nff-go/types"
)

var mixPattern = regexp.MustCompile(`^mix[0-9]*$`)
var pcapPattern = regexp.MustCompile(`^.*\.pcap$`)

type AddrRange struct {
	Min     uint64
	Max     uint64
	Current uint64
	Inc     uint64
}

// SequenceType used in enum below.
type SequenceType uint

// Types of Sequence.
const (
	RANDOM SequenceType = iota
	INCREASING
)

// Sequence contains type and next sequence value.
type Sequence struct {
	Type    SequenceType
	Current uint32
}

type DataType int

const (
	NULL = iota
	ETHERHDR
	IPv4HDR
	IPv6HDR
	TCPHDR
	UDPHDR
	ICMPHDR
	ARPHDR
	DATA
	PDISTDATA
	RANDDATA
	RAWDATA
	NONE
	PCAP
)

// PacketConfig configures packet
type PacketConfig struct {
	DType DataType
	Ether EtherConfig
	Pcap  PcapConfig
}

// MixConfig contains PacketConfigs with quantity.
type MixConfig struct {
	Config   PacketConfig
	Quantity uint32
}

func (mc *MixConfig) String() string {
	return fmt.Sprintf("config: %v; quantity: %v\n", mc.Config, mc.Quantity)
}

// PcapCOnfig configures pcap file
type PcapConfig struct {
	Path       string
	FileReader *os.File
	InMemory   bool
	ReachedEOF bool
	Packets    [][]byte
	NextPacket int
}

// EtherConfig configures ether header.
type EtherConfig struct {
	DAddr AddrRange
	SAddr AddrRange
	VLAN  *VlanTagConfig
	DType DataType
	IPv4  IPv4Config
	IPv6  IPv6Config
	ARP   ARPConfig
	Bytes RawBytes
}

// VlanTagConfig configures vlan tag
type VlanTagConfig struct {
	TCI uint16
}

// IPv4Config configures ip header.
type IPv4Config struct {
	SAddr AddrRange // source address
	DAddr AddrRange // destination address
	DType DataType
	TCP   TCPConfig
	UDP   UDPConfig
	ICMP  ICMPConfig
	Bytes RawBytes
}

// TCPConfig configures tcp header.
type TCPConfig struct {
	SPort AddrRange
	DPort AddrRange
	Seq   Sequence
	Flags types.TCPFlags
	DType DataType
	Bytes RawBytes
}

// UDPConfig configures tcp header.
type UDPConfig struct {
	SPort AddrRange
	DPort AddrRange
	DType DataType
	Bytes RawBytes
}

// ICMPConfig configures tcp header.
type ICMPConfig struct {
	Type       uint8
	Code       uint8
	Identifier uint16
	Seq        Sequence
	DType      DataType
	Bytes      RawBytes
}

// ARPConfig configures arp header.
type ARPConfig struct {
	Operation  uint16
	Gratuitous bool
	SHA        AddrRange
	SPA        AddrRange
	THA        AddrRange
	TPA        AddrRange
}

// PDistEntry gives data with associated probability of being chosen.
type PDistEntry struct {
	Probability float64
	DType       DataType
	Data        string
	Rand        RandBytes
}

// RandBytes gives  a payload of random bytes, of a given size.
// Optionally it is possible to specify a deviation.
type RandBytes struct {
	Size      uint32
	Deviation uint32
}

// Raw represents raw data
type RawBytes struct {
	Data  string
	Rand  RandBytes
	Dist  []PDistEntry
	DType DataType
}

type GeneratorConfig []MixConfig

// ParseConfigFile parses json config file and returns GeneratorConfig.
func ParseConfigFile(f *os.File) (config GeneratorConfig, err error) {
	r := bufio.NewReader(f)
	var in GeneratorConfig
	err = json.NewDecoder(r).Decode(&in)
	if err != nil {
		return nil, err
	}
	return in, nil
}

// UnmarshalJSON implements Unmarshaller interface for GeneratorConfig.
func (mca *GeneratorConfig) UnmarshalJSON(data []byte) error {
	var in map[string]interface{}
	err := json.Unmarshal(data, &in)
	if err != nil {
		return err
	}
	*mca, err = ParseConfig(in)
	return err
}

// ParseConfig parses json config and returns GeneratorConfig.
func ParseConfig(in map[string]interface{}) (config GeneratorConfig, err error) {
	for k, v := range in {
		key := strings.ToLower(k)
		switch {
		case key == "ether":
			etherConfig := v.(map[string]interface{})
			ethHdr, err := parseEtherHdr(etherConfig)
			if err != nil {
				return nil, fmt.Errorf("parseEtherHdr returned: %v", err)
			}
			pktConfig := PacketConfig{Ether: ethHdr, DType: ETHERHDR}
			return append(config, MixConfig{Config: pktConfig, Quantity: 1}), nil
		case key == "pcap":
			pcapConfig := v.(map[string]interface{})
			pcap, err := parsePcap(pcapConfig)
			if err != nil {
				return nil, fmt.Errorf("parsePcap returned: %v", err)
			}
			pktConfig := PacketConfig{Pcap: pcap, DType: PCAP}
			return append(config, MixConfig{Config: pktConfig, Quantity: 1}), nil
		case mixPattern.MatchString(key):
			return ParseGeneratorConfig(in)
		default:
			return nil, fmt.Errorf("unexpected key: %s, expected mix[0-9]* or ether", k)
		}
	}

	return nil, fmt.Errorf("expected 'ether' key , but did not get")
}

func ParseGeneratorConfig(in map[string]interface{}) (config GeneratorConfig, err error) {
	for k, v := range in {
		key := strings.ToLower(k)
		switch {
		case mixPattern.MatchString(key):
			var (
				pktConfig PacketConfig
				q         uint32
			)
			mixUnit := v.(map[string]interface{})
			for kk, vv := range mixUnit {
				switch strings.ToLower(kk) {
				case "ether":
					etherConfig := vv.(map[string]interface{})
					ethHdr, err := parseEtherHdr(etherConfig)
					if err != nil {
						return nil, fmt.Errorf("parseEtherHdr returned: %v", err)
					}
					pktConfig = PacketConfig{Ether: ethHdr, DType: ETHERHDR}
				case "pcap":
					pcapConfig := vv.(map[string]interface{})
					pcap, err := parsePcap(pcapConfig)
					if err != nil {
						return nil, fmt.Errorf("parsePcap returned: %v", err)
					}
					pktConfig = PacketConfig{Pcap: pcap, DType: PCAP}
				case "quantity", "q":
					q = uint32(vv.(float64))
				default:
					return nil, fmt.Errorf("unexpected key: %s, expected ether and quantity or q", k)
				}
			}
			if q == 0 || pktConfig.DType == NULL {
				return nil, fmt.Errorf("some fields were not set")
			}
			config = append(config, MixConfig{Config: pktConfig, Quantity: q})
		default:
			return nil, fmt.Errorf("unexpected key: %s, expected mix[0-9]*", k)
		}
	}
	return config, nil
}

func parseEtherHdr(in map[string]interface{}) (EtherConfig, error) {
	ethConfig := EtherConfig{DAddr: AddrRange{}, SAddr: AddrRange{}, VLAN: nil, DType: NONE}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "saddr":
			saddr, err := parseMacAddr(v)
			if err != nil {
				return EtherConfig{}, fmt.Errorf("parseMacAddr for ether saddr returned: %v", err)
			}
			ethConfig.SAddr = saddr
		case "daddr":
			daddr, err := parseMacAddr(v)
			if err != nil {
				return EtherConfig{}, fmt.Errorf("parseMacAddr for ether daddr returned: %v", err)
			}
			ethConfig.DAddr = daddr
		case "vlan-tci":
			ethConfig.VLAN = &(VlanTagConfig{TCI: uint16(v.(float64))})
			break
		case "ipv4":
			ipConf, err := parseIPv4Hdr(v.(map[string]interface{}))
			if err != nil {
				return EtherConfig{}, fmt.Errorf("parseIpHdr returned %v", err)
			}
			ethConfig.IPv4 = ipConf
			ethConfig.DType = IPv4HDR
			break
		case "ipv6":
			ipConf, err := parseIPv6Hdr(v.(map[string]interface{}))
			if err != nil {
				return EtherConfig{}, fmt.Errorf("parseIpHdr returned %v", err)
			}
			ethConfig.IPv6 = ipConf
			ethConfig.DType = IPv6HDR
			break
		case "arp":
			arpConfig := v.(map[string]interface{})
			arpConf, err := parseARPHdr(arpConfig)
			if err != nil {
				return EtherConfig{}, fmt.Errorf("parseARPHdr returned %v", err)
			}
			ethConfig.ARP = arpConf
			ethConfig.DType = ARPHDR
			break
		default:
			data, err := parseData(map[string]interface{}{k: v})
			if err != nil {
				return EtherConfig{}, fmt.Errorf("parseData for ether returned: %v", err)
			}
			ethConfig.Bytes = data
			ethConfig.DType = DATA
			break
		}
	}
	return ethConfig, nil
}

func parseData(in map[string]interface{}) (ret RawBytes, err error) {
	for k, v := range in {
		switch strings.ToLower(k) {
		case "raw":
			ret.Data, err = parseRaw(v.(map[string]interface{}))
			ret.DType = RAWDATA
			if err != nil {
				return ret, fmt.Errorf("parseRaw returned %v", err)
			}
			return ret, nil
		case "randbytes":
			ret.Rand, err = parseRandBytes(v.(map[string]interface{}))
			ret.DType = RANDDATA
			if err != nil {
				return ret, fmt.Errorf("parseRandBytes returned %v", err)
			}
			return ret, nil
		case "pdist":
			ret.Dist, err = parsePdist(v.([]interface{}))
			ret.DType = PDISTDATA
			if err != nil {
				return ret, fmt.Errorf("parsePdist returned %v", err)
			}
			return ret, nil
		default:
			fmt.Println("unknown key: ", k)
			break
		}
	}
	return ret, fmt.Errorf("failed to parse data")
}

func (ipv4 *IPv4Config) UnmarshalJSON(data []byte) error {
	var in map[string]interface{}
	err := json.Unmarshal(data, &in)
	if err != nil {
		return err
	}
	*ipv4, err = parseIPv4Hdr(in)
	return err
}

func parseIPv4Hdr(in map[string]interface{}) (IPv4Config, error) {
	ipHdr := IPv4Config{DAddr: AddrRange{}, SAddr: AddrRange{}}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "saddr":
			saddr, err := parseIPv4Addr(v)
			if err != nil {
				return IPv4Config{}, fmt.Errorf("parseIPv4Addr for ip saddr returned: %v", err)
			}
			ipHdr.SAddr = saddr
		case "daddr":
			daddr, err := parseIPv4Addr(v)
			if err != nil {
				return IPv4Config{}, fmt.Errorf("parseIPv4Addr for ip daddr returned: %v", err)
			}
			ipHdr.DAddr = daddr
		case "tcp":
			tcpConf, err := parseTCPHdr(v.(map[string]interface{}))
			if err != nil {
				return IPv4Config{}, fmt.Errorf("parseTCPHdr returned %v", err)
			}
			ipHdr.TCP = tcpConf
			ipHdr.DType = TCPHDR
			break
		case "udp":
			udpConf, err := parseUDPHdr(v.(map[string]interface{}))
			if err != nil {
				return IPv4Config{}, fmt.Errorf("parseUDPHdr returned %v", err)
			}
			ipHdr.UDP = udpConf
			ipHdr.DType = UDPHDR
			break
		case "icmp":
			icmpConf, err := parseICMPHdr(v.(map[string]interface{}))
			if err != nil {
				return IPv4Config{}, fmt.Errorf("parseICMPHdr returned %v", err)
			}
			ipHdr.ICMP = icmpConf
			ipHdr.DType = ICMPHDR
			break
		default:
			data, err := parseData(map[string]interface{}{k: v})
			if err != nil {
				return IPv4Config{}, fmt.Errorf("parseData for ip returned: %v", err)
			}
			ipHdr.Bytes = data
			ipHdr.DType = DATA
			break
		}
	}
	return ipHdr, nil
}

func parseARPHdr(in map[string]interface{}) (ARPConfig, error) {
	arpHdr := ARPConfig{Operation: 1, Gratuitous: false, SHA: AddrRange{}, SPA: AddrRange{}, THA: AddrRange{}, TPA: AddrRange{}}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "opcode":
			opcode := v.(float64)
			if opcode < 1 || opcode > 2 {
				return ARPConfig{}, fmt.Errorf("support opcodes [1,2], got: %d", uint16(opcode))
			}
			arpHdr.Operation = uint16(opcode)
		case "gratuitous":
			arpHdr.Gratuitous = v.(bool)
		case "sha":
			sha, err := parseMacAddr(v)
			if err != nil {
				return ARPConfig{}, fmt.Errorf("parseMacAddr for sha returned: %v", err)
			}
			arpHdr.SHA = sha
		case "spa":
			spa, err := parseIPv4Addr(v)
			if err != nil {
				return ARPConfig{}, fmt.Errorf("parseIPAddr for spa returned: %v", err)
			}
			arpHdr.SPA = spa
		case "tha":
			tha, err := parseMacAddr(v)
			if err != nil {
				return ARPConfig{}, fmt.Errorf("parseMacAddr for tha returned: %v", err)
			}
			arpHdr.THA = tha
		case "tpa":
			tpa, err := parseIPv4Addr(v)
			if err != nil {
				return ARPConfig{}, fmt.Errorf("parseIPAddr for tpa returned: %v", err)
			}
			arpHdr.TPA = tpa
		default:
			return ARPConfig{}, fmt.Errorf("unrecognized key for arp configuration: %s", k)
		}
	}
	return arpHdr, nil
}

func parseTCPHdr(in map[string]interface{}) (TCPConfig, error) {
	tcpHdr := TCPConfig{SPort: AddrRange{}, DPort: AddrRange{}}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "sport":
			sport, err := parsePort(v)
			if err != nil {
				return TCPConfig{}, fmt.Errorf("parsePort for tcp sport returned: %v", err)
			}
			tcpHdr.SPort = sport
		case "dport":
			dport, err := parsePort(v)
			if err != nil {
				return TCPConfig{}, fmt.Errorf("parsePort for tcp dport returned: %v", err)
			}
			tcpHdr.DPort = dport
		case "seq":
			seq, err := parseSeq(v.(string))
			if err != nil {
				return TCPConfig{}, fmt.Errorf("failed to parse tcp sequence: %v", err)
			}
			tcpHdr.Seq = seq
		case "flags":
			flags, err := parseTCPFlags(v.([]interface{}))
			if err != nil {
				return TCPConfig{}, fmt.Errorf("parseTCPFlags failed with %v", err)
			}
			tcpHdr.Flags = flags
		default:
			data, err := parseData(map[string]interface{}{k: v})
			if err != nil {
				return TCPConfig{}, fmt.Errorf("parseData for tcp returned: %v", err)
			}
			tcpHdr.Bytes = data
			break
		}
	}
	return tcpHdr, nil
}

func parseUDPHdr(in map[string]interface{}) (UDPConfig, error) {
	udpHdr := UDPConfig{SPort: AddrRange{}, DPort: AddrRange{}}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "sport":
			sport, err := parsePort(v)
			if err != nil {
				return UDPConfig{}, fmt.Errorf("parsePort for tcp sport returned: %v", err)
			}
			udpHdr.SPort = sport
		case "dport":
			dport, err := parsePort(v)
			if err != nil {
				return UDPConfig{}, fmt.Errorf("parsePort for tcp dport returned: %v", err)
			}
			udpHdr.DPort = dport
		default:
			data, err := parseData(map[string]interface{}{k: v})
			if err != nil {
				return UDPConfig{}, fmt.Errorf("parseData for udp returned: %v", err)
			}
			udpHdr.Bytes = data
			break
		}
	}
	return udpHdr, nil
}

func parseICMPHdr(in map[string]interface{}) (ICMPConfig, error) {
	icmpHdr := ICMPConfig{Bytes: RawBytes{Data: ""}}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "type":
			icmpHdr.Type = uint8(v.(float64))
		case "code":
			icmpHdr.Code = uint8(v.(float64))
		case "identifier", "id":
			icmpHdr.Identifier = uint16(v.(float64))
		case "seq", "seqnum":
			seq, err := parseSeq(v.(string))
			if err != nil {
				return ICMPConfig{}, fmt.Errorf("failed to parse icmp sequence: %v", err)
			}
			icmpHdr.Seq = seq
		default:
			data, err := parseData(map[string]interface{}{k: v})
			if err != nil {
				return ICMPConfig{}, fmt.Errorf("parseData for icmp returned: %v", err)
			}
			icmpHdr.Bytes = data
			break
		}
	}
	return icmpHdr, nil
}

func parseTCPFlags(in []interface{}) (ret types.TCPFlags, err error) {
	ret = 0
	for _, flag := range in {
		switch strings.ToLower(flag.(string)) {
		case "fin":
			ret ^= types.TCPFlagFin
		case "syn":
			ret ^= types.TCPFlagSyn
		case "rst":
			ret ^= types.TCPFlagRst
		case "psh":
			ret ^= types.TCPFlagPsh
		case "ack":
			ret ^= types.TCPFlagAck
		case "urg":
			ret ^= types.TCPFlagUrg
		case "ece":
			ret ^= types.TCPFlagEce
		case "cwr":
			ret ^= types.TCPFlagCwr
		default:
			return 0, fmt.Errorf("unknown flag value: %s", flag.(string))
		}
	}
	return ret, nil
}

func parseSeq(in string) (Sequence, error) {
	switch strings.ToLower(in) {
	case "rand", "random":
		return Sequence{Type: RANDOM, Current: rand.Uint32()}, nil
	case "incr", "increasing":
		return Sequence{Type: INCREASING, Current: 0}, nil
	}
	return Sequence{}, fmt.Errorf("unknown key for tcp sequence: %s", in)
}

func parseRaw(in map[string]interface{}) (string, error) {
	for k, v := range in {
		switch strings.ToLower(k) {
		case "data":
			return v.(string), nil
		default:
			return "", fmt.Errorf("unknown key in 'raw' block: %s", k)
		}
	}

	return "", fmt.Errorf("no key 'data' found inside 'raw' block")
}

func parseRandBytes(in map[string]interface{}) (RandBytes, error) {
	rBytes := RandBytes{}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "size":
			if v.(float64) < 0 {
				return RandBytes{}, fmt.Errorf("invalid size value, should be positive: %f", v.(float64))
			}
			rBytes.Size = (uint32)(v.(float64))
		case "deviation":
			if v.(float64) < 0 {
				return RandBytes{}, fmt.Errorf("invalid deviation value, should be positive: %f", v.(float64))
			}
			rBytes.Deviation = (uint32)(v.(float64))
		}
	}
	if rBytes.Size < rBytes.Deviation {
		return RandBytes{}, fmt.Errorf("deviation cant be larger than size")
	}
	return rBytes, nil
}

func parsePdist(in []interface{}) ([]PDistEntry, error) {
	pdist := []PDistEntry{}
	var totalProb float64
	for _, v := range in {
		pdistElem, err := parsePdistEntry(v.(map[string]interface{}))
		if err != nil {
			return []PDistEntry{}, fmt.Errorf("parsing pdistentry returned: %v", err)
		}
		totalProb += pdistElem.Probability
		pdist = append(pdist, pdistElem)
	}
	if totalProb != 1 {
		return []PDistEntry{{}}, fmt.Errorf("Sum of probabilities of pdist elements is not equal to 1")
	}
	return pdist, nil
}

func parsePdistEntry(in map[string]interface{}) (pdistElem PDistEntry, err error) {
	for k, v := range in {
		switch strings.ToLower(k) {
		case "probability":
			pdistElem.Probability = v.(float64)
			if pdistElem.Probability > 1 || pdistElem.Probability < 0 {
				return PDistEntry{}, fmt.Errorf("invalid probability value: %f", pdistElem.Probability)
			}
		case "raw":
			pdistElem.Data, err = parseRaw(v.(map[string]interface{}))
			if err != nil {
				return PDistEntry{}, fmt.Errorf("parsing pdist entry: parseRaw returned %v", err)
			}
			pdistElem.DType = RAWDATA
		case "randbytes":
			pdistElem.Rand, err = parseRandBytes(v.(map[string]interface{}))
			if err != nil {
				return PDistEntry{}, fmt.Errorf("parsing pdist entry: parseRandBytes returned %v", err)
			}
			pdistElem.DType = RANDDATA
		default:
			return PDistEntry{}, fmt.Errorf("unknown key %s", k)
		}
	}
	return pdistElem, nil
}

func parseMacAddr(value interface{}) (ret AddrRange, err error) {
	switch v2 := value.(type) {
	case map[string]interface{}:
		for k, v := range v2 {
			switch strings.ToLower(k) {
			case "range":
				saddrRange, err := parseAddrRange(v.(map[string]interface{}), parseRawMACAddr)
				if err != nil {
					return AddrRange{}, fmt.Errorf("parseAddrRange returned: %v", err)
				}
				return saddrRange, nil
			default:
				return AddrRange{}, fmt.Errorf("unknown key in parse mac addr: %s", k)
			}
		}
	case string:
		ret.Current, err = parseRawMACAddr(v2)
		if err != nil {
			return AddrRange{}, fmt.Errorf("parsing mac saddr returned: %v", err)
		}
		return ret, nil
	}
	return AddrRange{}, fmt.Errorf("unknown type")
}

func parseRawIPv4Addr(rawAddr string) (uint64, error) {
	addr := net.ParseIP(rawAddr)
	if addr == nil {
		return 0, fmt.Errorf("parsing ip addr could not parse address for %s", rawAddr)
	}
	return uint64(addr[12])<<24 | uint64(addr[13])<<16 | uint64(addr[14])<<8 | uint64(addr[15]), nil
}

func parseRawMACAddr(rawAddr string) (uint64, error) {
	addr, err := net.ParseMAC(rawAddr)
	if err != nil {
		return 0, fmt.Errorf("parsing mac addr returned: %v for %s", err, rawAddr)
	}
	return uint64(addr[0])<<40 | uint64(addr[1])<<32 | uint64(addr[2])<<24 | uint64(addr[3])<<16 | uint64(addr[4])<<8 | uint64(addr[5]), nil
}

func parseIPv4Addr(value interface{}) (ret AddrRange, err error) {
	switch v2 := value.(type) {
	case map[string]interface{}:
		for k, v := range v2 {
			switch strings.ToLower(k) {
			case "range":
				addrRange, err := parseAddrRange(v.(map[string]interface{}), parseRawIPv4Addr)
				if err != nil {
					return AddrRange{}, fmt.Errorf("parseAddrRange returned: %v", err)
				}
				return addrRange, nil
			default:
				return AddrRange{}, fmt.Errorf("unknown key in ip addr: %s", k)
			}
		}
	case string:
		ret.Current, err = parseRawIPv4Addr(v2)
		if err != nil {
			return AddrRange{}, fmt.Errorf("parsing ip addr returned: %v", err)
		}
		return ret, nil
	}
	return AddrRange{}, fmt.Errorf("unknown type")
}

type fn func(string) (uint64, error)

func parseAddrRange(in map[string]interface{}, parseFunc fn) (addr AddrRange, err error) {
	wasMin, wasMax, wasStart, wasInc := false, false, false, false
	for k, v := range in {
		switch strings.ToLower(k) {
		case "min":
			addr.Min, err = parseFunc(v.(string))
			if err != nil {
				return AddrRange{}, fmt.Errorf("parsing min returned: %v", err)
			}
			wasMin = true
		case "max":
			addr.Max, err = parseFunc(v.(string))
			if err != nil {
				return AddrRange{}, fmt.Errorf("parsing max returned: %v", err)
			}
			wasMax = true
		case "start":
			addr.Current, err = parseFunc(v.(string))
			if err != nil {
				return AddrRange{}, fmt.Errorf("parsing start returned: %v", err)
			}
			wasStart = true
		case "inc":
			addr.Inc = (uint64)(v.(float64))
			wasInc = true
		default:
			return AddrRange{}, fmt.Errorf("unknown key %s", k)
		}
	}
	if !wasMax || !wasMin {
		return AddrRange{}, fmt.Errorf("Min and max values should be given for range")
	}
	if addr.Max < addr.Min {
		return AddrRange{}, fmt.Errorf("Min value should be less than Max")
	}
	if !wasStart {
		addr.Current = addr.Min
	}

	if addr.Current < addr.Min || addr.Current > addr.Max {
		return AddrRange{}, fmt.Errorf(fmt.Sprintf("Start value should be between min and max: start=%v, min=%v, max=%v", addr.Current, addr.Min, addr.Max))
	}
	if !wasInc {
		addr.Inc = 1
	}
	return addr, nil
}

func parsePort(in interface{}) (AddrRange, error) {
	switch v2 := in.(type) {
	case map[string]interface{}:
		for k, v := range v2 {
			switch strings.ToLower(k) {
			case "range":
				portRng, err := parsePortRange(v.(map[string]interface{}))
				if err != nil {
					return AddrRange{}, fmt.Errorf("parseAddrRange returned: %v", err)
				}
				return portRng, nil
			default:
				return AddrRange{}, fmt.Errorf("unknown key in port: %s", k)
			}
		}
	case float64:
		if in.(float64) < 0 {
			return AddrRange{}, fmt.Errorf("Port should be positive")
		}
		port := (uint64)(in.(float64))
		return AddrRange{Min: port, Max: port, Current: port, Inc: 0}, nil
	}
	return AddrRange{}, fmt.Errorf("unknown type")
}

func parsePortRange(in map[string]interface{}) (AddrRange, error) {
	portRng := AddrRange{Inc: 0}
	wasMin, wasMax, wasStart, wasInc := false, false, false, false
	for k, v := range in {
		switch strings.ToLower(k) {
		case "min":
			if v.(float64) < 0 {
				return AddrRange{}, fmt.Errorf("Min should be positive")
			}
			portRng.Min = (uint64)(v.(float64))
			wasMin = true
		case "max":
			if v.(float64) < 0 {
				return AddrRange{}, fmt.Errorf("Max should be positive")
			}
			portRng.Max = (uint64)(v.(float64))
			wasMax = true
		case "start":
			if v.(float64) < 0 {
				return AddrRange{}, fmt.Errorf("Start should be positive")
			}
			portRng.Current = (uint64)(v.(float64))
			wasStart = true
		case "inc":
			if v.(float64) < 0 {
				return AddrRange{}, fmt.Errorf("Inc should be positive")
			}
			portRng.Inc = (uint64)(v.(float64))
			wasInc = true
		default:
			return AddrRange{}, fmt.Errorf("unknown key %s", k)
		}
	}
	if !wasMax || !wasMin {
		return AddrRange{}, fmt.Errorf("Min and max values should be given for range")
	}
	if portRng.Max < portRng.Min {
		return AddrRange{}, fmt.Errorf("Min value should be <= Max value")
	}
	if !wasStart {
		portRng.Current = portRng.Min
	}
	if portRng.Current < portRng.Min || portRng.Current > portRng.Max {
		return AddrRange{}, fmt.Errorf("Start should be in range of min and max")
	}
	if !wasInc {
		portRng.Inc = 1
	}
	return portRng, nil
}

func parsePcap(in map[string]interface{}) (PcapConfig, error) {
	pcap := PcapConfig{}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "path":
			path, ok := v.(string)
			if !ok {
				return PcapConfig{}, fmt.Errorf("parsePcapConfig for path returned: not a string")
			}
			if !pcapPattern.MatchString(path) {
				return PcapConfig{}, fmt.Errorf("parsePcapConfig for path returned: invalid pcap file")
			}
			pcap.Path = path
		case "inmemory":
			inmemory, ok := v.(bool)
			if !ok {
				return PcapConfig{}, fmt.Errorf("parsePcapConfig for inmemory returned: not a bool")
			}
			pcap.InMemory = inmemory
		}
	}
	return pcap, nil
}
