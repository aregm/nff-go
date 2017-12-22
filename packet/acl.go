// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package packet provides functionality for checking and comparing packets.
// Besides parsing packets user can request comparing packets. In some flow functions
// user needs to compare packet with some rules, for example access control lists.
// It can be done manually after packet parsing, however YANFF library provides more
// convenient way for checking and comparing packets via rules.
//
// Rules construction
//
// Rules should be constructed before their usage via "get" functions.
// Three such functions are provided:
// 		GetL2ACLFromJSON
// 		GetL3ACLFromJSON
// 		GetL3ACLFromORIG
// GetL2RulesFromORIG function for L2 level is not added yet. TODO
// These functions should be used before any usage of rules, however they also can be
// used dynamically in parallel which make a possibility of changing rules during execution.
//
// After rules are constructed the four functions can be used to filter packets according to rules:
// 		L2ACLPermit
//		L2ACLPort
//		L3ACLPermit
// 		L3ACLPort
package packet

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/intel-go/yanff/common"
)

type rawL2Rule struct {
	Rule        string
	Source      string
	Destination string
	ID          string
}

type rawL2Rules struct {
	L2Rules []rawL2Rule
}

type rawL3Rule struct {
	SrcAddr      string
	DstAddr      string
	ID           string
	SrcPort      string
	DstPort      string
	OutputNumber string
}

type rawL3Rules struct {
	L3Rules []rawL3Rule
}

// GetL2ACLFromJSON gets name of JSON structed file with L2 rules,
// returns L2Rules
func GetL2ACLFromJSON(filename string) (*L2Rules, error) {
	var rawRules rawL2Rules
	var rules L2Rules
	// Load Rules
	f, err := readFile(filename)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(f, &rawRules); err != nil {
		return nil, common.WrapWithNFError(err, "JSON error during rules parsing", common.ParseRuleJSONErr)
	}
	// Parse Rules
	return &rules, rawL2Parse(&rawRules, &rules)
}

// GetL2ACLFromORIG gets name of fields structed file with combined L2 rules,
// returns L2Rules
func GetL2ACLFromORIG(filename string) (*L2Rules, error) {
	var rawRules rawL2Rules
	var rules L2Rules
	// Load Rules
	file, err := os.Open(filename)
	if err != nil {
		return nil, common.WrapWithNFError(err, "file error during rules parsing ", common.FileErr)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		temp := scanner.Text()
		if len(temp) == 0 || temp[0] == '#' {
			continue
		}
		lines := strings.Fields(temp)
		if len(lines) == 3 {
			lines = append(lines, "false")
		} else if len(lines) != 4 {
			return nil, common.WrapWithNFError(nil, "Incomplete 3-tuple for rule parsing", common.ParseRuleErr)
		}
		rawRules.L2Rules = append(rawRules.L2Rules, rawL2Rule{Source: lines[0],
			Destination: lines[1], ID: lines[2], Rule: lines[3]})
	}
	if err := scanner.Err(); err != nil {
		return nil, common.WrapWithNFError(err, "file error during rules parsing ", common.FileErr)
	}
	file.Close()

	// Parse Rules
	return &rules, rawL2Parse(&rawRules, &rules)
}

// GetL3ACLFromJSON gets name of JSON structed file with combined L3 and L4 rules,
// returns L2Rules
func GetL3ACLFromJSON(filename string) (*L3Rules, error) {
	var rawRules rawL3Rules
	var rules L3Rules
	// Load Rules
	f, err := readFile(filename)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(f, &rawRules); err != nil {
		return nil, common.WrapWithNFError(err, "JSON error during rules parsing", common.ParseRuleJSONErr)
	}
	// Parse Rules
	return &rules, rawL3Parse(&rawRules, &rules)
}

func readFile(filename string) ([]byte, error) {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, common.WrapWithNFError(err, "file error during rules parsing", common.FileErr)
	}
	return file, nil
}

//TODO we need to construct raw structure as one after one without storing all them in memory

// GetL3ACLFromORIG gets name of fields structed file with combined L3 and L4 rules,
// returns L3Rules
func GetL3ACLFromORIG(filename string) (*L3Rules, error) {
	var rawRules rawL3Rules
	var rules L3Rules
	// Load Rules
	file, err := os.Open(filename)
	if err != nil {
		return nil, common.WrapWithNFError(err, "file error during rules parsing", common.FileErr)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		temp := scanner.Text()
		if len(temp) == 0 || temp[0] == '#' {
			continue
		}
		lines := strings.Fields(temp)
		if len(lines) == 5 {
			lines = append(lines, "false")
		} else if len(lines) != 6 {
			return nil, common.WrapWithNFError(nil, "Incomplete 5-tuple for rule parsing", common.ParseRuleErr)
		}
		rawRules.L3Rules = append(rawRules.L3Rules, rawL3Rule{SrcAddr: lines[0], DstAddr: lines[1],
			ID: lines[2], SrcPort: lines[3], DstPort: lines[4], OutputNumber: lines[5]})
	}
	if err := scanner.Err(); err != nil {
		return nil, common.WrapWithNFError(err, "file error during rules parsing", common.FileErr)
	}
	file.Close()

	// Parse Rules
	return &rules, rawL3Parse(&rawRules, &rules)
}

func rawL2Parse(rules *rawL2Rules, jp *L2Rules) error {
	jup := rules.L2Rules
	jp.eth = make([]l2Rules, len(jup))
	for i := 0; i < len(jup); i++ {
		var err error
		jp.eth[i].OutputNumber, err = parseRuleResult(jup[i].Rule)
		if err != nil {
			return err
		}

		if jup[i].Source != "ANY" {
			jp.eth[i].SAddrNotAny = true
			t, err := net.ParseMAC(jup[i].Source)
			if err != nil {
				return common.WrapWithNFError(err, fmt.Sprintf("Incorrect source MAC: %v", jup[i].Source), common.IncorrectArgInRules)
			}
			copy(jp.eth[i].SAddr[:], t)
		}
		if jup[i].Destination != "ANY" {
			jp.eth[i].DAddrNotAny = true
			t, err := net.ParseMAC(jup[i].Destination)
			if err != nil {
				return common.WrapWithNFError(err, fmt.Sprintf("Incorrect destination MAC: %v", jup[i].Destination), common.IncorrectArgInRules)
			}
			copy(jp.eth[i].DAddr[:], t)
		}
		switch jup[i].ID {
		case "ANY":
			jp.eth[i].ID = 0
			jp.eth[i].IDMask = 0
		case "ipv4", "Ipv4", "IPv4", "IPV4", "0x0800":
			jp.eth[i].ID = common.IPV4Number
			jp.eth[i].IDMask = 0xffff
		case "ipv6", "Ipv6", "IPv6", "IPV6", "0x86dd":
			jp.eth[i].ID = common.IPV6Number
			jp.eth[i].IDMask = 0xffff
		case "arp", "Arp", "ARP", "0x0806":
			jp.eth[i].ID = common.ARPNumber
			jp.eth[i].IDMask = 0xffff
		default:
			return common.WrapWithNFError(nil, fmt.Sprintf("Incorrect  L3 protocol ID: %v", jup[i].ID), common.IncorrectArgInRules)
		}
	}
	return nil
}

func rawL3Parse(rules *rawL3Rules, jp *L3Rules) error {
	jup := rules.L3Rules
	var validSrc, validDst bool
	var srcAddr, dstAddr *net.IPNet
	_, zero4, _ := net.ParseCIDR("0.0.0.0/0")
	_, zero6, _ := net.ParseCIDR("::/0")
	var temp4 l3Rules4
	var temp6 l3Rules6
	var l4temp l4Rules
	var srcLen, dstLen uint8
	jp.ip4 = make([]l3Rules4, 0, len(jup))
	jp.ip6 = make([]l3Rules6, 0, len(jup))
	for i := 0; i < len(jup); i++ {
		// Parse L4 ID
		switch jup[i].ID {
		case "ANY":
			l4temp.ID = 0
			l4temp.IDMask = 0
		case "tcp", "TCP", "Tcp", "0x06", "6":
			l4temp.ID = common.TCPNumber
			l4temp.IDMask = 0xff
		case "udp", "UDP", "Udp", "0x11", "17":
			l4temp.ID = common.UDPNumber
			l4temp.IDMask = 0xff
		case "icmp", "ICMP", "Icmp", "0x01", "1":
			l4temp.ID = common.ICMPNumber
			l4temp.IDMask = 0xff
			if jup[i].SrcPort != "ANY" || jup[i].DstPort != "ANY" {
				return common.WrapWithNFError(nil, "Incorrect request: for ICMP rule Source port and Destination port should be ANY", common.IncorrectArgInRules)
			}
		default:
			return common.WrapWithNFError(nil, fmt.Sprintf("Incorrect  L4 protocol ID: %v", jup[i].ID), common.IncorrectArgInRules)
		}
		var err error
		// Parse L4 ports
		l4temp.SrcPortMin, l4temp.SrcPortMax, validSrc, err = parseL4Port(jup[i].SrcPort)
		if err != nil {
			return err
		}
		l4temp.DstPortMin, l4temp.DstPortMax, validDst, err = parseL4Port(jup[i].DstPort)
		if err != nil {
			return err
		}
		l4temp.valid = validSrc || validDst

		// Parse L3 addresses
		if jup[i].SrcAddr == "ANY" {
			srcLen = 0
		} else {
			_, srcAddr, _ = net.ParseCIDR(jup[i].SrcAddr)
			srcLen = uint8(len(srcAddr.IP))
		}
		if jup[i].DstAddr == "ANY" {
			dstLen = 0
		} else {
			_, dstAddr, _ = net.ParseCIDR(jup[i].DstAddr)
			dstLen = uint8(len(dstAddr.IP))
		}

		if srcLen == 0 {
			temp4.SrcAddr, temp4.SrcMask = parseAddr4(zero4)
			temp6.SrcAddr, temp6.SrcMask = parseAddr6(zero6)
			if dstLen == 0 {
				// Both src and dst are ANY. Need to create rules for both ip4 and ip6
				temp4.DstAddr, temp4.DstMask = parseAddr4(zero4)
				temp4.OutputNumber, err = parseRuleResult(jup[i].OutputNumber)
				if err != nil {
					return err
				}
				temp4.L4 = l4temp
				jp.ip4 = append(jp.ip4, temp4)

				temp6.DstAddr, temp6.DstMask = parseAddr6(zero6)
				temp6.OutputNumber, err = parseRuleResult(jup[i].OutputNumber)
				if err != nil {
					return err
				}
				temp6.L4 = l4temp
				jp.ip6 = append(jp.ip6, temp6)
			} else if dstLen == 4 {
				temp4.DstAddr, temp4.DstMask = parseAddr4(dstAddr)
				temp4.OutputNumber, err = parseRuleResult(jup[i].OutputNumber)
				if err != nil {
					return err
				}
				temp4.L4 = l4temp
				jp.ip4 = append(jp.ip4, temp4)
			} else if dstLen == 16 {
				temp6.DstAddr, temp6.DstMask = parseAddr6(dstAddr)
				temp6.OutputNumber, err = parseRuleResult(jup[i].OutputNumber)
				if err != nil {
					return err
				}
				temp6.L4 = l4temp
				jp.ip6 = append(jp.ip6, temp6)
			}
		} else if srcLen == 4 {
			temp4.SrcAddr, temp4.SrcMask = parseAddr4(srcAddr)
			if dstLen == 0 {
				temp4.DstAddr, temp4.DstMask = parseAddr4(zero4)
			} else if dstLen == 4 {
				temp4.DstAddr, temp4.DstMask = parseAddr4(dstAddr)
			} else if dstLen == 16 {
				return common.WrapWithNFError(nil, "Incorrect request: IPv4 + IPv6 in one rule", common.IncorrectArgInRules)
			}
			temp4.OutputNumber, err = parseRuleResult(jup[i].OutputNumber)
			if err != nil {
				return err
			}
			temp4.L4 = l4temp
			jp.ip4 = append(jp.ip4, temp4)
		} else if srcLen == 16 {
			temp6.SrcAddr, temp6.SrcMask = parseAddr6(srcAddr)
			if dstLen == 0 {
				temp6.DstAddr, temp6.DstMask = parseAddr6(zero6)
			} else if dstLen == 4 {
				return common.WrapWithNFError(nil, "Incorrect request: IPv4 + IPv6 in one rule", common.IncorrectArgInRules)
			} else if dstLen == 16 {
				temp6.DstAddr, temp6.DstMask = parseAddr6(dstAddr)
			}
			temp6.OutputNumber, err = parseRuleResult(jup[i].OutputNumber)
			if err != nil {
				return err
			}
			temp6.L4 = l4temp
			jp.ip6 = append(jp.ip6, temp6)
		}
	}
	return nil
}

func parseL4Port(port string) (uint16, uint16, bool, error) {
	valid := true
	// We accept all ports
	if port == "ANY" || port == "0:65535" {
		tMin := 0
		tMax := 65535
		valid = false
		return uint16(tMin), uint16(tMax), valid, nil
	}
	// We accept only one port. It should be Min and Max simultaneously
	if strings.Index(port, ":") == -1 {
		port = port + ":" + port
	}
	s := strings.SplitN(port, ":", 2)
	if len(s) != 2 {
		return 0, 0, false, common.WrapWithNFError(nil, fmt.Sprintf("Incorrect port: %v", port), common.IncorrectArgInRules)
	}
	tMin, errMin := strconv.ParseUint(s[0], 10, 16)
	tMax, errMax := strconv.ParseUint(s[1], 10, 16)
	if errMin != nil || errMax != nil {
		return 0, 0, false, common.WrapWithNFError(nil, fmt.Sprintf("Incorrect request: cannot parse Min and Max port values in %v", port), common.IncorrectArgInRules)
	}
	if tMin > tMax {
		return 0, 0, false, common.WrapWithNFError(nil, fmt.Sprintf("Incorrect request: minPort > maxPort, port: %v", port), common.IncorrectArgInRules)
	}
	return uint16(tMin), uint16(tMax), valid, nil
}

func parseRuleResult(rule string) (uint, error) {
	switch rule {
	case "Accept", "true":
		return 1, nil
	case "Reject", "false":
		return 0, nil
	default:
		port, err := strconv.ParseUint(rule, 10, 32)
		if err != nil {
			return 0, common.WrapWithNFError(nil, fmt.Sprintf("Incorrect rule: %v", rule), common.IncorrectRule)
		}
		return uint(port), nil
	}
}

func parseAddr4(addr *net.IPNet) (uint32, uint32) {
	return binary.LittleEndian.Uint32(addr.IP), binary.LittleEndian.Uint32(addr.Mask)
}

func parseAddr6(addr *net.IPNet) ([16]uint8, [16]uint8) {
	var addr1 [16]uint8
	var mask1 [16]uint8

	copy(addr1[:], addr.IP.To16())
	copy(mask1[:], addr.Mask)
	return addr1, mask1
}

type l2Rules struct {
	OutputNumber uint
	DAddrNotAny  bool
	SAddrNotAny  bool
	DAddr        [6]uint8
	SAddr        [6]uint8
	IDMask       uint16
	ID           uint16
}

type l4Rules struct {
	ID         uint8
	IDMask     uint8
	valid      bool
	SrcPortMin uint16
	SrcPortMax uint16
	DstPortMin uint16
	DstPortMax uint16
}

type l3Rules4 struct {
	OutputNumber uint
	SrcAddr      uint32
	DstAddr      uint32
	SrcMask      uint32
	DstMask      uint32
	L4           l4Rules
}

type l3Rules6 struct {
	OutputNumber uint
	SrcAddr      [16]uint8
	DstAddr      [16]uint8
	SrcMask      [16]uint8
	DstMask      [16]uint8
	L4           l4Rules
}

// L3Rules - struct for rules of l3 level
type L3Rules struct {
	ip4 []l3Rules4
	ip6 []l3Rules6
}

// L2Rules - struct for rules of l2 level
type L2Rules struct {
	eth []l2Rules
}

// L2ACLPermit gets packet (with parsed L2) and L2Rules.
// Returns accept or reject for this packet
func (pkt *Packet) L2ACLPermit(rules *L2Rules) bool {
	if pkt.l2ACL(rules) > 0 {
		return true
	}
	return false
}

// L2ACLPort gets packet (with parsed L2) and L2Rules.
// Returns number of output for packet
func (pkt *Packet) L2ACLPort(rules *L2Rules) uint {
	return pkt.l2ACL(rules)
}

func (pkt *Packet) l2ACL(rules *L2Rules) uint {
	for _, rule := range rules.eth {
		if rule.SAddrNotAny == true && rule.SAddr != pkt.Ether.SAddr {
			continue
		}
		if rule.DAddrNotAny == true && rule.DAddr != pkt.Ether.DAddr {
			continue
		}
		if (rule.ID^SwapBytesUint16(pkt.Ether.EtherType))&rule.IDMask != 0 {
			continue
		}
		return rule.OutputNumber
	}
	return 0
}

// L3ACLPermit gets packet (with parsed L3 or L3 with L4) and L3Rules.
// Returns accept or reject for this packet
func (pkt *Packet) L3ACLPermit(rules *L3Rules) bool {
	if pkt.l3ACL(rules) > 0 {
		return true
	}
	return false
}

// L3ACLPort gets packet (with parsed L3 or L3 with L4) and L3Rules.
// Returns number of output for this packet
func (pkt *Packet) L3ACLPort(rules *L3Rules) uint {
	return pkt.l3ACL(rules)
}

func (pkt *Packet) l4ACL(L4 *l4Rules) bool {
	// Src and Dst port numbers placed at the same offset from L4 start in both tcp and udp
	l4 := (*UDPHdr)(pkt.L4)
	srcPort := SwapBytesUint16(l4.SrcPort)
	if srcPort < L4.SrcPortMin || srcPort > L4.SrcPortMax {
		return false
	}
	dstPort := SwapBytesUint16(l4.DstPort)
	if dstPort < L4.DstPortMin || dstPort > L4.DstPortMax {
		return false
	}
	return true
}

func (pkt *Packet) l3ACL(rules *L3Rules) uint {
	ipv4, ipv6, _ := pkt.ParseAllKnownL3()
	if ipv4 != nil {
		for _, rule := range rules.ip4 {
			if ((rule.SrcAddr ^ ipv4.SrcAddr) & rule.SrcMask) != 0 {
				continue
			}
			if ((rule.DstAddr ^ ipv4.DstAddr) & rule.DstMask) != 0 {
				continue
			}
			if ((rule.L4.ID ^ ipv4.NextProtoID) & rule.L4.IDMask) != 0 {
				continue
			}
			if rule.L4.valid {
				pkt.ParseL4ForIPv4()
				if !pkt.l4ACL(&rule.L4) {
					continue
				}
			}
			return rule.OutputNumber
		}
	} else if ipv6 != nil {
	IPv6:
		for _, rule := range rules.ip6 {
			for i := 0; i < 16; i++ {
				if ((rule.SrcAddr[i]^ipv6.SrcAddr[i])&rule.SrcMask[i] != 0) ||
					((rule.DstAddr[i]^ipv6.DstAddr[i])&rule.DstMask[i] != 0) {
					continue IPv6
				}
			}
			if ((rule.L4.ID ^ ipv6.Proto) & rule.L4.IDMask) != 0 {
				continue
			}
			pkt.ParseL4ForIPv6()
			if !pkt.l4ACL(&rule.L4) {
				continue
			}
			return rule.OutputNumber
		}
	} else {
		return 0
	}
	return 0
}
