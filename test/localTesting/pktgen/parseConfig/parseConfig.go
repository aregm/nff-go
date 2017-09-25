package parseConfig

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"

	"github.com/intel-go/yanff/common"
)

// TODO: ARP packets are not supported yet

// AddrRange describes range of addresses.
type AddrRange struct {
	Min   []uint8
	Max   []uint8
	Start []uint8
	Incr  uint64
}

// PortRange describes range of ports.
type PortRange struct {
	Min   uint16
	Max   uint16
	Start []uint16
	Incr  uint16
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
	Type SequenceType
	Next []uint32
}

// PacketConfig configures packet
type PacketConfig struct {
	Data interface{}
}

// EtherConfig configures ether header.
type EtherConfig struct {
	DAddr AddrRange
	SAddr AddrRange
	Data  interface{}
}

// IPConfig configures ip header.
type IPConfig struct {
	Version int
	SAddr   AddrRange // source address
	DAddr   AddrRange // destination address
	Data    interface{}
}

// TCPConfig configures tcp header.
type TCPConfig struct {
	SPort PortRange
	DPort PortRange
	Seq   Sequence
	Flags common.TCPFlags
	Data  interface{}
}

// UDPConfig configures tcp header.
type UDPConfig struct {
	SPort PortRange
	DPort PortRange
	Data  interface{}
}

// ICMPConfig configures tcp header.
type ICMPConfig struct {
	Type       uint8
	Code       uint8
	Identifier uint16
	Seq        Sequence
	Data       interface{}
}

// PDistEntry gives data with associated probability of being chosen.
type PDistEntry struct {
	Probability float64
	Data        interface{}
}

// RandBytes gives  a payload of random bytes, of a given size.
// Optionally it is possible to specify a deviation.
type RandBytes struct {
	Size      uint32
	Deviation uint32
}

// Raw represents raw data
type Raw struct {
	Data string
}

// ParsePacketConfig parses json config and returns structure.
func ParsePacketConfig(f *os.File) (*PacketConfig, error) {
	r := bufio.NewReader(f)
	var in map[string]interface{}
	err := json.NewDecoder(r).Decode(&in)
	if err != nil {
		return nil, fmt.Errorf("decoding input from file returned: %v", err)
	}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "ether":
			etherConfig := v.(map[string]interface{})
			ethHdr, err := parseEtherHdr(etherConfig)
			if err != nil {
				return nil, fmt.Errorf("parseEtherHdr returned: %v", err)
			}
			return &PacketConfig{Data: ethHdr}, nil
		default:
			return nil, fmt.Errorf("unexpected key: %s", k)
		}
	}

	return nil, fmt.Errorf("expected 'ether' key , but did not get")
}

func parseEtherHdr(in map[string]interface{}) (EtherConfig, error) {
	ethConfig := EtherConfig{}
	wasDaddr := false
	wasSaddr := false
	wasData := false
	for k, v := range in {
		switch strings.ToLower(k) {
		case "saddr":
			saddr, err := parseMacAddr(v)
			if err != nil {
				return EtherConfig{}, fmt.Errorf("parseMacAddr for ether saddr returned: %v", err)
			}
			ethConfig.SAddr = saddr
			wasSaddr = true
		case "daddr":
			daddr, err := parseMacAddr(v)
			if err != nil {
				return EtherConfig{}, fmt.Errorf("parseMacAddr for ether daddr returned: %v", err)
			}
			ethConfig.DAddr = daddr
			wasDaddr = true
		case "ip":
			ipConf, err := parseIPHdr(v.(map[string]interface{}))
			if err != nil {
				return EtherConfig{}, fmt.Errorf("parseIpHdr returned %v", err)
			}
			ethConfig.Data = ipConf
			wasData = true
			break
		default:
			data, err := parseData(map[string]interface{}{k: v})
			if err != nil {
				return EtherConfig{}, fmt.Errorf("parseData for ether returned: %v", err)
			}
			ethConfig.Data = data
			wasData = true
			break
		}
	}
	if !wasDaddr {
		ethConfig.DAddr = AddrRange{}
	}
	if !wasSaddr {
		ethConfig.SAddr = AddrRange{}
	}
	if !wasData {
		ethConfig.Data = Raw{Data: ""}
	}
	return ethConfig, nil
}

func parseData(in map[string]interface{}) (interface{}, error) {
	for k, v := range in {
		switch strings.ToLower(k) {
		case "raw":
			data, err := parseRaw(v.(map[string]interface{}))
			if err != nil {
				return nil, fmt.Errorf("parseRaw returned %v", err)
			}
			return data, nil
		case "randbytes":
			randBytes, err := parseRandBytes(v.(map[string]interface{}))
			if err != nil {
				return nil, fmt.Errorf("parseRandBytes returned %v", err)
			}
			return randBytes, nil
		case "pdist":
			pdist, err := parsePdist(v.([]interface{}))
			if err != nil {
				return nil, fmt.Errorf("parsePdist returned %v", err)
			}
			return pdist, nil
		default:
			fmt.Println("unknown key: ", k)
			break
		}
	}
	return nil, fmt.Errorf("failed to parse data")
}

func parseIPHdr(in map[string]interface{}) (IPConfig, error) {
	ipHdr := IPConfig{}
	wasVersion := false
	wasSaddr := false
	wasDaddr := false
	wasData := false
	for k, v := range in {
		switch strings.ToLower(k) {
		case "version":
			version := (int)(v.(float64))
			if version != 4 && version != 6 {
				return IPConfig{}, fmt.Errorf("ip version should be 4 or 6, got: %d", version)
			}
			ipHdr.Version = version
			wasVersion = true
		case "saddr":
			saddr, err := parseIPAddr(v)
			if err != nil {
				return IPConfig{}, fmt.Errorf("parseIPAddr for ip saddr returned: %v", err)
			}
			ipHdr.SAddr = saddr
			wasSaddr = true
		case "daddr":
			daddr, err := parseIPAddr(v)
			if err != nil {
				return IPConfig{}, fmt.Errorf("parseIPAddr for ip daddr returned: %v", err)
			}
			ipHdr.DAddr = daddr
			wasDaddr = true
		case "tcp":
			tcpConf, err := parseTCPHdr(v.(map[string]interface{}))
			if err != nil {
				return IPConfig{}, fmt.Errorf("parseTCPHdr returned %v", err)
			}
			ipHdr.Data = tcpConf
			wasData = true
			break
		case "udp":
			udpConf, err := parseUDPHdr(v.(map[string]interface{}))
			if err != nil {
				return IPConfig{}, fmt.Errorf("parseUDPHdr returned %v", err)
			}
			ipHdr.Data = udpConf
			wasData = true
			break
		case "icmp":
			icmpConf, err := parseICMPHdr(v.(map[string]interface{}))
			if err != nil {
				return IPConfig{}, fmt.Errorf("parseICMPHdr returned %v", err)
			}
			ipHdr.Data = icmpConf
			wasData = true
			break
		default:
			data, err := parseData(map[string]interface{}{k: v})
			if err != nil {
				return IPConfig{}, fmt.Errorf("parseData for ip returned: %v", err)
			}
			ipHdr.Data = data
			wasData = true
			break
		}
	}
	if !wasVersion {
		ipHdr.Version = 4
	}
	if !wasDaddr {
		ipHdr.DAddr = AddrRange{}
	}
	if !wasSaddr {
		ipHdr.SAddr = AddrRange{}
	}
	if !wasData {
		ipHdr.Data = Raw{Data: ""}
	}
	return ipHdr, nil
}

func parseTCPHdr(in map[string]interface{}) (TCPConfig, error) {
	tcpHdr := TCPConfig{}
	wasDport := false
	wasSport := false
	wasData := false
	for k, v := range in {
		switch strings.ToLower(k) {
		case "sport":
			sport, err := parsePort(v)
			if err != nil {
				return TCPConfig{}, fmt.Errorf("parsePort for tcp sport returned: %v", err)
			}
			tcpHdr.SPort = sport
			wasSport = true
		case "dport":
			dport, err := parsePort(v)
			if err != nil {
				return TCPConfig{}, fmt.Errorf("parsePort for tcp dport returned: %v", err)
			}
			tcpHdr.DPort = dport
			wasDport = true
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
			tcpHdr.Data = data
			wasData = true
			break
		}
	}
	if !wasDport {
		tcpHdr.DPort = PortRange{}
	}
	if !wasSport {
		tcpHdr.SPort = PortRange{}
	}
	if !wasData {
		tcpHdr.Data = Raw{Data: ""}
	}
	return tcpHdr, nil
}

func parseUDPHdr(in map[string]interface{}) (UDPConfig, error) {
	udpHdr := UDPConfig{}
	wasDport := false
	wasSport := false
	wasData := false
	for k, v := range in {
		switch strings.ToLower(k) {
		case "sport":
			sport, err := parsePort(v)
			if err != nil {
				return UDPConfig{}, fmt.Errorf("parsePort for tcp sport returned: %v", err)
			}
			udpHdr.SPort = sport
			wasSport = true
		case "dport":
			dport, err := parsePort(v)
			if err != nil {
				return UDPConfig{}, fmt.Errorf("parsePort for tcp dport returned: %v", err)
			}
			udpHdr.DPort = dport
			wasDport = true
		default:
			data, err := parseData(map[string]interface{}{k: v})
			if err != nil {
				return UDPConfig{}, fmt.Errorf("parseData for udp returned: %v", err)
			}
			udpHdr.Data = data
			wasData = true
			break
		}
	}
	if !wasDport {
		udpHdr.DPort = PortRange{}
	}
	if !wasSport {
		udpHdr.SPort = PortRange{}
	}
	if !wasData {
		udpHdr.Data = Raw{Data: ""}
	}
	return udpHdr, nil
}

func parseICMPHdr(in map[string]interface{}) (ICMPConfig, error) {
	icmpHdr := ICMPConfig{}
	wasData := false
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
			icmpHdr.Data = data
			wasData = true
			break
		}
	}

	if !wasData {
		icmpHdr.Data = Raw{Data: ""}
	}
	return icmpHdr, nil
}

func parseTCPFlags(in []interface{}) (ret common.TCPFlags, err error) {
	ret = 0
	for _, flag := range in {
		switch strings.ToLower(flag.(string)) {
		case "fin":
			ret ^= common.TCPFlagFin
		case "syn":
			ret ^= common.TCPFlagSyn
		case "rst":
			ret ^= common.TCPFlagRst
		case "psh":
			ret ^= common.TCPFlagPsh
		case "ack":
			ret ^= common.TCPFlagAck
		case "urg":
			ret ^= common.TCPFlagUrg
		case "ece":
			ret ^= common.TCPFlagEce
		case "cwr":
			ret ^= common.TCPFlagCwr
		default:
			return 0, fmt.Errorf("unknown flag value: %s", flag.(string))
		}
	}
	return ret, nil
}

func parseSeq(in string) (Sequence, error) {
	switch strings.ToLower(in) {
	case "rand", "random":
		return Sequence{Type: RANDOM, Next: []uint32{rand.Uint32()}}, nil
	case "incr", "increasing":
		return Sequence{Type: INCREASING, Next: []uint32{0}}, nil
	}
	return Sequence{}, fmt.Errorf("unknown key for tcp sequence: %s", in)
}

func parseRaw(in map[string]interface{}) (Raw, error) {
	for k, v := range in {
		switch strings.ToLower(k) {
		case "data":
			return Raw{Data: v.(string)}, nil
		default:
			return Raw{}, fmt.Errorf("unknown key in 'raw' block: %s", k)
		}
	}

	return Raw{}, fmt.Errorf("no key 'data' found inside 'raw' block")
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
	for _, v := range in {
		pdistElem, err := parsePdistEntry(v.(map[string]interface{}))
		if err != nil {
			return []PDistEntry{}, fmt.Errorf("parsing pdistentry returned: %v", err)
		}
		pdist = append(pdist, pdistElem)
	}
	return pdist, nil
}

func parsePdistEntry(in map[string]interface{}) (PDistEntry, error) {
	pdistElem := PDistEntry{}
	for k, v := range in {
		switch strings.ToLower(k) {
		case "probability":
			pdistElem.Probability = v.(float64)
			if pdistElem.Probability > 1 || pdistElem.Probability < 0 {
				return PDistEntry{}, fmt.Errorf("invalid probability value: %f", pdistElem.Probability)
			}
		case "raw":
			data, err := parseRaw(v.(map[string]interface{}))
			if err != nil {
				return PDistEntry{}, fmt.Errorf("parsing pdist entry: parseRaw returned %v", err)
			}
			pdistElem.Data = data
		case "randbytes":
			randBytes, err := parseRandBytes(v.(map[string]interface{}))
			if err != nil {
				return PDistEntry{}, fmt.Errorf("parsing pdist entry: parseRandBytes returned %v", err)
			}
			pdistElem.Data = randBytes
		default:
			return PDistEntry{}, fmt.Errorf("unknown key %s", k)
		}
	}
	return pdistElem, nil
}

func parseMacAddr(value interface{}) (AddrRange, error) {
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
		saddr, err := net.ParseMAC(v2)
		if err != nil {
			return AddrRange{}, fmt.Errorf("parsing mac saddr returned: %v", err)
		}
		return AddrRange{Min: saddr, Max: saddr, Start: saddr, Incr: 0}, nil
	}
	return AddrRange{}, fmt.Errorf("unknown type")
}

func parseRawIPAddr(rawAddr string) ([]uint8, error) {
	addr := net.ParseIP(rawAddr)
	if addr == nil {
		return nil, fmt.Errorf("parsing ip addr could not parse address for %s", rawAddr)
	}
	return addr, nil
}

func parseRawMACAddr(rawAddr string) ([]uint8, error) {
	addr, err := net.ParseMAC(rawAddr)
	if err != nil {
		return nil, fmt.Errorf("parsing mac addr returned: %v for %s", err, rawAddr)
	}
	return addr, nil
}

func parseIPAddr(value interface{}) (AddrRange, error) {
	switch v2 := value.(type) {
	case map[string]interface{}:
		for k, v := range v2 {
			switch strings.ToLower(k) {
			case "range":
				addrRange, err := parseAddrRange(v.(map[string]interface{}), parseRawIPAddr)
				if err != nil {
					return AddrRange{}, fmt.Errorf("parseAddrRange returned: %v", err)
				}
				return addrRange, nil
			default:
				return AddrRange{}, fmt.Errorf("unknown key in ip addr: %s", k)
			}
		}
	case string:
		addr, err := parseRawIPAddr(v2)
		if err != nil {
			return AddrRange{}, fmt.Errorf("parsing ip addr returned: %v", err)
		}
		return AddrRange{Min: addr, Max: addr, Start: addr, Incr: 0}, nil
	}
	return AddrRange{}, fmt.Errorf("unknown type")
}

type fn func(string) ([]uint8, error)

func parseAddrRange(in map[string]interface{}, parseFunc fn) (AddrRange, error) {
	addr := AddrRange{}
	wasMin, wasMax, wasStart, wasIncr := false, false, false, false
	for k, v := range in {
		switch strings.ToLower(k) {
		case "min":
			min, err := parseFunc(v.(string))
			if err != nil {
				return AddrRange{}, fmt.Errorf("parsing min returned: %v", err)
			}
			addr.Min = min
			wasMin = true
		case "max":
			max, err := parseFunc(v.(string))
			if err != nil {
				return AddrRange{}, fmt.Errorf("parsing max returned: %v", err)
			}
			addr.Max = max
			wasMax = true
		case "start":
			start, err := parseFunc(v.(string))
			if err != nil {
				return AddrRange{}, fmt.Errorf("parsing start returned: %v", err)
			}
			addr.Start = start
			wasStart = true
		case "incr":
			addr.Incr = (uint64)(v.(float64))
			wasIncr = true
		default:
			return AddrRange{}, fmt.Errorf("unknown key %s", k)
		}
	}
	if !wasMax || !wasMin {
		return AddrRange{}, fmt.Errorf("Min and max values should be given for range")
	}
	if bytes.Compare(addr.Max, addr.Min) < 0 {
		return AddrRange{}, fmt.Errorf("Min value should be less than Max")
	}
	if !wasStart {
		addr.Start = addr.Min
	}
	if bytes.Compare(addr.Start, addr.Min) < 0 || bytes.Compare(addr.Start, addr.Max) > 0 {
		return AddrRange{}, fmt.Errorf("Start value should be between min and max")
	}
	if !wasIncr {
		addr.Incr = 0
	}
	return addr, nil
}

func parsePort(in interface{}) (PortRange, error) {
	switch v2 := in.(type) {
	case map[string]interface{}:
		for k, v := range v2 {
			switch strings.ToLower(k) {
			case "range":
				portRng, err := parsePortRange(v.(map[string]interface{}))
				if err != nil {
					return PortRange{}, fmt.Errorf("parseAddrRange returned: %v", err)
				}
				return portRng, nil
			default:
				return PortRange{}, fmt.Errorf("unknown key in port: %s", k)
			}
		}
	case float64:
		if in.(float64) < 0 {
			return PortRange{}, fmt.Errorf("Port should be positive")
		}
		port := (uint16)(in.(float64))
		return PortRange{Min: port, Max: port, Start: []uint16{port}, Incr: 0}, nil
	}
	return PortRange{}, fmt.Errorf("unknown type")
}

func parsePortRange(in map[string]interface{}) (PortRange, error) {
	portRng := PortRange{}
	wasMin, wasMax, wasStart, wasIncr := false, false, false, false
	for k, v := range in {
		switch strings.ToLower(k) {
		case "min":
			if v.(float64) < 0 {
				return PortRange{}, fmt.Errorf("Min should be positive")
			}
			portRng.Min = (uint16)(v.(float64))
			wasMin = true
		case "max":
			if v.(float64) < 0 {
				return PortRange{}, fmt.Errorf("Max should be positive")
			}
			portRng.Max = (uint16)(v.(float64))
			wasMax = true
		case "start":
			if v.(float64) < 0 {
				return PortRange{}, fmt.Errorf("Start should be positive")
			}
			portRng.Start = []uint16{(uint16)(v.(float64))}
			wasStart = true
		case "incr":
			if v.(float64) < 0 {
				return PortRange{}, fmt.Errorf("Incr should be positive")
			}
			portRng.Incr = (uint16)(v.(float64))
			wasIncr = true
		default:
			return PortRange{}, fmt.Errorf("unknown key %s", k)
		}
	}
	if !wasMax || !wasMin {
		return PortRange{}, fmt.Errorf("Min and max values should be given for range")
	}
	if portRng.Max < portRng.Min {
		return PortRange{}, fmt.Errorf("Min value should be <= Max value")
	}
	if !wasStart {
		portRng.Start = []uint16{portRng.Min}
	}
	if portRng.Start[0] < portRng.Min || portRng.Start[0] > portRng.Max {
		return PortRange{}, fmt.Errorf("Start should be in range of min and max")
	}
	if !wasIncr {
		portRng.Incr = 0
	}
	return portRng, nil
}
