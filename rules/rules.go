// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rules implements functionality for checking and comparing packets.
// Besides parsing packets user can request comparing packets. In some flow functions
// user needs to compare packet with some rules, for example access control lists.
// It can be done manually after packet parsing, however YANFF library provides more
// convenient way for checking and comparing packets via rules.
//
// Rules construction
//
// Rules should be constructed before their usage via "get" functions.
// Three such functions are provided:
// 		GetL2RulesFromJSON
// 		GetL3RulesFromJSON
// 		GetL3RulesFromORIG
// GetL2RulesFromORIG function for L2 level is not added yet. TODO
// These functions should be used before any usage of rules, however they also can be
// used dynamically in parallel which make a possibility of changing rules during execution.
//
// After rules are constructed the four functions can be used to filter packets according to rules:
// 		L2_ACL_permit
//		L2_ACL_port
//		L3_ACL_permit
// 		L3_ACL_port
package rules

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"net"
	"nfv/common"
	"nfv/packet"
	"os"
	"strconv"
	"strings"
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

// GetL2RulesFromJSON gets name of JSON structed file with L2 rules,
// returns L2Rules
func GetL2RulesFromJSON(filename string) *L2Rules {
	var rawRules rawL2Rules
	var rules L2Rules
	// Load Rules
	err := json.Unmarshal(readFile(filename), &rawRules)
	if err != nil {
		common.LogError(common.Debug, "JSON error during rules parsing: ", err)
	}
	// Parse Rules
	rawL2Parse(&rawRules, &rules)
	return &rules
}

// GetL3RulesFromJSON gets name of JSON structed file with combined L3 and L4 rules,
// returns L2Rules
func GetL3RulesFromJSON(filename string) *L3Rules {
	var rawRules rawL3Rules
	var rules L3Rules
	// Load Rules
	err := json.Unmarshal(readFile(filename), &rawRules)
	if err != nil {
		common.LogError(common.Debug, "JSON error during rules parsing: ", err)
	}
	// Parse Rules
	rawL3Parse(&rawRules, &rules)
	return &rules
}

func readFile(filename string) []byte {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		common.LogError(common.Debug, "File error during rules parsing: ", err)
	}
	return file
}

//TODO we need to construct raw structure as one after one without storing all them in memory

// GetL3RulesFromORIG gets name of fields structed file with combined L3 and L4 rules,
// returns L3Rules
func GetL3RulesFromORIG(filename string) *L3Rules {
	var rawRules rawL3Rules
	var rules L3Rules
	// Load Rules
	file, err := os.Open(filename)
	if err != nil {
		common.LogError(common.Debug, "File error during rules parsing: ", err)
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
			common.LogError(common.Debug, "Not compelte 5-tuple for rule parsing")
		}
		rawRules.L3Rules = append(rawRules.L3Rules, rawL3Rule{SrcAddr: lines[0], DstAddr: lines[1],
			ID: lines[2], SrcPort: lines[3], DstPort: lines[4], OutputNumber: lines[5]})
	}
	if err := scanner.Err(); err != nil {
		common.LogError(common.Debug, "File error during rules parsing: ", err)
	}
	file.Close()

	// Parse Rules
	rawL3Parse(&rawRules, &rules)
	return &rules
}

func rawL2Parse(rules *rawL2Rules, jp *L2Rules) {
	jup := rules.L2Rules
	jp.eth = make([]l2Rules, len(jup))
	for i := 0; i < len(jup); i++ {
		jp.eth[i].OutputNumber = parseRuleResult(jup[i].Rule)
		if jup[i].Source != "ANY" {
			jp.eth[i].SAddrNotAny = true
			t, err := net.ParseMAC(jup[i].Source)
			if err != nil {
				common.LogError(common.Debug, "Incorrect JSON request: ", jup[i].Source)
			}
			copy(jp.eth[i].SAddr[:], t)
		}
		if jup[i].Destination != "ANY" {
			jp.eth[i].DAddrNotAny = true
			t, err := net.ParseMAC(jup[i].Destination)
			if err != nil {
				common.LogError(common.Debug, "Incorrect JSON request: ", jup[i].Destination)
			}
			copy(jp.eth[i].DAddr[:], t)
		}
		switch jup[i].ID {
		case "ANY":
			jp.eth[i].ID = 0
			jp.eth[i].IDMask = 0
		case "ipv4", "Ipv4", "IPv4", "IPV4", "0x0800":
			jp.eth[i].ID = packet.IPV4Number
			jp.eth[i].IDMask = 0xffff
		case "ipv6", "Ipv6", "IPv6", "IPV6", "0x86dd":
			jp.eth[i].ID = packet.IPV6Number
			jp.eth[i].IDMask = 0xffff
		default:
			common.LogError(common.Debug, "Incorrect JSON request: ", jup[i].ID)
		}
	}
}

func rawL3Parse(rules *rawL3Rules, jp *L3Rules) {
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
			l4temp.ID = packet.TCPNumber
			l4temp.IDMask = 0xff
		case "udp", "UDP", "Udp", "0x11", "17":
			l4temp.ID = packet.UDPNumber
			l4temp.IDMask = 0xff
		default:
			common.LogError(common.Debug, "Incorrect JSON request: ", jup[i].ID)
		}

		// Parse L4 ports
		l4temp.SrcPortMin, l4temp.SrcPortMax, validSrc = parseL4Port(jup[i].SrcPort)
		l4temp.DstPortMin, l4temp.DstPortMax, validDst = parseL4Port(jup[i].DstPort)
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
				temp4.OutputNumber = parseRuleResult(jup[i].OutputNumber)
				temp4.L4 = l4temp
				jp.ip4 = append(jp.ip4, temp4)

				temp6.DstAddr, temp6.DstMask = parseAddr6(zero6)
				temp6.OutputNumber = parseRuleResult(jup[i].OutputNumber)
				temp6.L4 = l4temp
				jp.ip6 = append(jp.ip6, temp6)
			} else if dstLen == 4 {
				temp4.DstAddr, temp4.DstMask = parseAddr4(dstAddr)
				temp4.OutputNumber = parseRuleResult(jup[i].OutputNumber)
				temp4.L4 = l4temp
				jp.ip4 = append(jp.ip4, temp4)
			} else if dstLen == 16 {
				temp6.DstAddr, temp6.DstMask = parseAddr6(dstAddr)
				temp6.OutputNumber = parseRuleResult(jup[i].OutputNumber)
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
				common.LogError(common.Debug, "Incorrect JSON request: IPv4 + IPv6 in one rule")
			}
			temp4.OutputNumber = parseRuleResult(jup[i].OutputNumber)
			temp4.L4 = l4temp
			jp.ip4 = append(jp.ip4, temp4)
		} else if srcLen == 16 {
			temp6.SrcAddr, temp6.SrcMask = parseAddr6(srcAddr)
			if dstLen == 0 {
				temp6.DstAddr, temp6.DstMask = parseAddr6(zero6)
			} else if dstLen == 4 {
				common.LogError(common.Debug, "Incorrect JSON request: IPv4 + IPv6 in one rule")
			} else if dstLen == 16 {
				temp6.DstAddr, temp6.DstMask = parseAddr6(dstAddr)
			}
			temp6.OutputNumber = parseRuleResult(jup[i].OutputNumber)
			temp6.L4 = l4temp
			jp.ip6 = append(jp.ip6, temp6)
		}
	}
}

func parseL4Port(port string) (uint16, uint16, bool) {
	valid := true
	// We accept all ports
	if port == "ANY" || port == "0:65535" {
		tMin := 0
		tMax := 65535
		valid = false
		return uint16(tMin), uint16(tMax), valid
	}
	// We accept only one port. It should be Min and Max simultaneously
	if strings.Index(port, ":") == -1 {
		port = port + ":" + port
	}
	s := strings.SplitN(port, ":", 2)
	if len(s) != 2 {
		common.LogError(common.Debug, "Incorrect JSON request: ", port)
	}
	tMin, errMin := strconv.ParseUint(s[0], 10, 16)
	tMax, errMax := strconv.ParseUint(s[1], 10, 16)
	if errMin != nil || errMax != nil {
		common.LogError(common.Debug, "Incorrect JSON request: ", port)
	}
	if tMin > tMax {
		common.LogError(common.Debug, "Incorrect JSON request: minPort > maxPort", port)
	}
	return uint16(tMin), uint16(tMax), valid
}

func parseRuleResult(rule string) uint {
	switch rule {
	case "Accept", "true":
		return 1
	case "Reject", "false":
		return 0
	default:
		port, err := strconv.ParseUint(rule, 10, 32)
		if err != nil {
			common.LogError(common.Debug, "Incorrect JSON request: ", rule)
		}
		return uint(port)
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

type L3Rules struct {
	ip4 []l3Rules4
	ip6 []l3Rules6
}

type L2Rules struct {
	eth []l2Rules
}

// L2_ACL_permit gets packet (with parsed L2) and L2Rules.
// Returns accept or reject for this packet
func L2_ACL_permit(pkt *packet.Packet, rules *L2Rules) bool {
	if l2_ACL(pkt, rules) > 0 {
		return true
	} else {
		return false
	}
}

// L2_ACL_port gets packet (with parsed L2) and L2Rules.
// Returns number of output for packet
func L2_ACL_port(pkt *packet.Packet, rules *L2Rules) uint {
	return l2_ACL(pkt, rules)
}

func l2_ACL(pkt *packet.Packet, rules *L2Rules) uint {
	for _, rule := range rules.eth {
		if rule.SAddrNotAny == true && rule.SAddr != pkt.Ether.SAddr {
			continue
		}
		if rule.DAddrNotAny == true && rule.DAddr != pkt.Ether.DAddr {
			continue
		}
		if (rule.ID^packet.SwapBytesUint16(pkt.Ether.EtherType))&rule.IDMask != 0 {
			continue
		}
		return rule.OutputNumber
	}
	return 0
}

// L3_ACL_permit gets packet (with parsed L3 or L3 with L4) and L3Rules.
// Returns accept or reject for this packet
func L3_ACL_permit(pkt *packet.Packet, rules *L3Rules) bool {
	if l3_ACL(pkt, rules) > 0 {
		return true
	} else {
		return false
	}
}

// L3_ACL_port gets packet (with parsed L3 or L3 with L4) and L3Rules.
// Returns number of output for this packet
func L3_ACL_port(pkt *packet.Packet, rules *L3Rules) uint {
	return l3_ACL(pkt, rules)
}

func l4_ACL(pkt *packet.Packet, L4 *l4Rules) bool {
	if pkt.TCP != nil {
		srcPort := packet.SwapBytesUint16(pkt.TCP.SrcPort)
		if srcPort < L4.SrcPortMin || srcPort > L4.SrcPortMax {
			return false
		}
		dstPort := packet.SwapBytesUint16(pkt.TCP.DstPort)
		if dstPort < L4.DstPortMin || dstPort > L4.DstPortMax {
			return false
		}
	} else if pkt.UDP != nil {
		srcPort := packet.SwapBytesUint16(pkt.UDP.SrcPort)
		if srcPort < L4.SrcPortMin || srcPort > L4.SrcPortMax {
			return false
		}
		dstPort := packet.SwapBytesUint16(pkt.UDP.DstPort)
		if dstPort < L4.DstPortMin || dstPort > L4.DstPortMax {
			return false
		}
	} else {
		// This situation takes place when we request any protocol ID at previous stage
		// however packet has neither TCP nor UDP protocols.
		return false
	}
	return true
}

func l3_ACL(pkt *packet.Packet, rules *L3Rules) uint {
	if pkt.IPv4 != nil {
		for _, rule := range rules.ip4 {
			if ((rule.SrcAddr ^ pkt.IPv4.SrcAddr) & rule.SrcMask) != 0 {
				continue
			}
			if ((rule.DstAddr ^ pkt.IPv4.DstAddr) & rule.DstMask) != 0 {
				continue
			}
			if ((rule.L4.ID ^ pkt.IPv4.NextProtoID) & rule.L4.IDMask) != 0 {
				continue
			}
			if rule.L4.valid && !l4_ACL(pkt, &rule.L4) {
				continue
			}
			return rule.OutputNumber
		}
	} else if pkt.IPv6 != nil {
	IPv6:
		for _, rule := range rules.ip6 {
			for i := 0; i < 16; i++ {
				if ((rule.SrcAddr[i]^pkt.IPv6.SrcAddr[i])&rule.SrcMask[i] != 0) ||
					((rule.DstAddr[i]^pkt.IPv6.DstAddr[i])&rule.DstMask[i] != 0) {
					continue IPv6
				}
			}
			if ((rule.L4.ID ^ pkt.IPv6.Proto) & rule.L4.IDMask) != 0 {
				continue
			}
			if rule.L4.valid && !l4_ACL(pkt, &rule.L4) {
				continue
			}
			return rule.OutputNumber
		}
	} else {
		return 0
	}
	return 0
}
