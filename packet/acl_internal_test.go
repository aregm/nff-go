// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

// Adding new testcase:
// You need to add desired value to rulesCtxt, in form of
// {raw_value, ground_truth_value}, by analogy with the already added
// Nothing else should be changed
// When add one value - it will combine in Courtesian product with other
// existing raw_values, so it genetrates many test cases

/*
Details
Parsing tests description

Complete Test flow is:
1) Generate raw rule
2) Write raw rule to tmp json file
3) Read it from file with function, which is being tested and get output
4) Generate ground truth result
5) Compare output with ground truth result

Each test is organized as follows:

1)Test has context declared (rulesCtxt) in the beginning.
It keeps data, from which test rule-config files will be generated.
This rulesCtxt keeps sets of pairs {raw_value, ground_truth_value}

  raw_value 			- value of type string
  ground_truth_value 	- expected result of parsing for this raw_value. It is value of some specific type, not string

There are such pairs for each field of the tested rule struct.

Example:
Look at TestL2RulesReadingGen function below
In its rulesCtxt declared test values for fields of rawl2Rule struct:
type rawL2Rule struct {
	Rule        string
	Source      string
	Destination string
	ID          string
}
Here there are 4 sets created in rulesCtxt: rules, srcs, dsts, ids

2) Then testing rules are generated.
Each rule is Courtesian product of raw_values from rulesCtxt sets.

3) Expected output is also generated. It is created by combining
the corresponding ground_truth_values from rulesCtxt.
*/

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/intel-go/yanff/low"
)

var mempool *low.Mempool

func init() {
	mempool = GetMempoolForTest()
}

// Data to generate L2 rules
var rulesL2Ctxt = rawL2RuleTestCtxt{
	rules: []ruleTest{ // {rawrule, ground truth rule}
		{"Accept", 1},
		{"Reject", 0},
		{"3", 3},
		{"", 0}, // case only for ORIG
	},
	srcs: []macAddrTest{ // {rawaddr, ground truth addr info {macaddr, addrNotAny}}
		{"ANY", gtMacAddr{[6]uint8{0, 0, 0, 0, 0, 0}, false}},
		{"00:11:22:33:44:55", gtMacAddr{[6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, true}},
	},
	dsts: []macAddrTest{ // {rawaddr, ground truth addr info {macaddr, addrNotAny}}
		{"ANY", gtMacAddr{[6]uint8{0, 0, 0, 0, 0, 0}, false}},
		{"01:11:21:31:41:51", gtMacAddr{[6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51}, true}},
	},
	ids: []idTest{ // {rawid, ground truth {id, idmask}}
		{"ANY", gtID{0, 0x0000}},
		{"IPv4", gtID{0x0800, 0xffff}},
		{"IPv6", gtID{0x86dd, 0xffff}},
		{"arp", gtID{0x0806, 0xffff}},
	},
}

// Data to generate L3 rules
var rulesL3Ctxt = rawL3RuleTestCtxt{
	srcs4: []Addr4Test{ // {rawaddr, ground truth addr info {macaddr, addrNotAny}}
		{"ANY", gtAddr4{0x00000000, 0x00000000}},
		{"127.0.0.1/31", gtAddr4{0x0000007f, 0xfeffffff}},
	},
	dsts4: []Addr4Test{ // {rawaddr, ground truth addr info}
		{"ANY", gtAddr4{0x00000000, 0x00000000}},
		{"128.9.9.5/24", gtAddr4{0x00090980, 0x00ffffff}},
	},
	srcs6: []Addr6Test{ // {rawaddr, ground truth addr info {macaddr, addrNotAny}}
		{"ANY",
			gtAddr6{
				[16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				[16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
		{"::/0",
			gtAddr6{
				[16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				[16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
		{"dead::beaf/16",
			gtAddr6{
				[16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				[16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
	},
	dsts6: []Addr6Test{ // {rawaddr, ground truth addr info}
		{"ANY",
			gtAddr6{
				[16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				[16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
		{"::/0",
			gtAddr6{
				[16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				[16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
		{"dead::beaf/128",
			gtAddr6{
				[16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xaf},
				[16]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			},
		},
	},
	ids: []idTest{ // {rawid, ground truth {id, idmask}}
		{"ANY", gtID{0, 0x0000}},
		{"TCP", gtID{0x06, 0xff}},
		{"UDP", gtID{0x11, 0xff}},
		{"ICMP", gtID{0x01, 0xff}},
	},
	srcports: []portTest{
		{"ANY", gtPort{0, 65535, false}},
		{"1222", gtPort{1222, 1222, true}},
		{"0:222", gtPort{0, 222, true}},
	},
	dstports: []portTest{
		{"ANY", gtPort{0, 65535, false}},
		{"1222", gtPort{1222, 1222, true}},
	},
	rules: []ruleTest{
		{"Accept", 1},
		{"Reject", 0},
		{"3", 3},
		{"", 0}, // case only for ORIG
	},
}

type testL2Rule struct {
	raw  rawL2Rules // Input raw data from file
	want l2Rules    // Expected result of parsing
}

type testL3Rule struct {
	raw   rawL3Rules // Input raw data from file
	want4 l3Rules4   // Expected result of parsing
	want6 l3Rules6   // Expected result of parsing
}

func generateTestL2Rules(rulesCtxt rawL2RuleTestCtxt, orig bool) []testL2Rule {
	var testTable []testL2Rule
	var decisions []ruleTest

	if !orig {
		decisions = rulesCtxt.rules[:2]
	}

	for _, r := range decisions {
		for _, src := range rulesCtxt.srcs {
			for _, dst := range rulesCtxt.dsts {
				for _, id := range rulesCtxt.ids {

					ruleWant := l2Rules{
						OutputNumber: r.gtrule,
						DAddrNotAny:  dst.addrNotAny,
						SAddrNotAny:  src.addrNotAny,
						DAddr:        dst.addr,
						SAddr:        src.addr,
						IDMask:       id.idmsk,
						ID:           id.id,
					}

					rule := rawL2Rules{
						L2Rules: []rawL2Rule{
							{
								Rule:        r.rawrule,
								Source:      src.rawaddr,
								Destination: dst.rawaddr,
								ID:          id.rawid,
							},
						},
					}
					testTable = append(testTable, testL2Rule{raw: rule, want: ruleWant})
				}
			}
		}
	}
	return testTable
}

// Function to test L2 rules parser for JSON
// L2 rules generated, written to json, then parsed
func TestGetL2ACLFromJSON(t *testing.T) {
	testTable := generateTestL2Rules(rulesL2Ctxt, false)

	tmpdir := createTmpDir("tmpTestGetL2ACLFromJSONConfigs")

	for _, rule := range testTable {
		nice, _ := json.Marshal(rule.raw)
		tmpfile := createTmpFile(tmpdir, "tmp_test.json")
		if _, err := tmpfile.WriteString(string(nice)); err != nil {
			log.Fatal(err)
		}

		ruleGot, err := GetL2ACLFromJSON(tmpfile.Name())
		if err != nil {
			log.Fatal(err)
		}

		if !reflect.DeepEqual(ruleGot.eth[0], rule.want) {
			t.Errorf("Incorrect parse L2 rules from JSON:\ngot: %+v \nwant: %+v\n\n",
				ruleGot.eth[0], rule.want)
			t.Errorf("Test ORIG file %s\n\n", tmpfile.Name())
			t.FailNow()
		}
		closeAndRemove(tmpfile)
	}
	removeIfEmpty(tmpdir)
}

// Function to test L2 rules parser for ORIG format
// L2 rules generated, written to ORIG format, then parsed
func TestGetL2ACLFromORIG(t *testing.T) {
	testTable := generateTestL2Rules(rulesL2Ctxt, true)

	tmpdir := createTmpDir("tmpTestGetL2ACLFromORIGConfigs")

	for _, rule := range testTable {
		headerORIG := "# Source MAC, Destination MAC, L3 ID, Output port\n"
		r := rule.raw.L2Rules[0]
		ruleORIG := fmt.Sprintf("%s %s %s %s", r.Source, r.Destination, r.ID, r.Rule)

		tmpfile := createTmpFile(tmpdir, "tmp_test.orig")
		if _, err := tmpfile.WriteString(headerORIG + ruleORIG); err != nil {
			log.Fatal(err)
		}

		ruleGot, err := GetL2ACLFromORIG(tmpfile.Name())
		if err != nil {
			t.Errorf("GetL2ACLFromORIG returned error %v\n\n", err)
			t.FailNow()
		}

		if !reflect.DeepEqual(ruleGot.eth[0], rule.want) {
			t.Errorf("Incorrect parse L2 rules from ORIG:\ngot: %+v \nwant: %+v\n\n",
				ruleGot.eth[0], rule.want)
			t.Errorf("Test ORIG file %s\n\n", tmpfile.Name())
			t.FailNow()
		}
		closeAndRemove(tmpfile)
	}
	removeIfEmpty(tmpdir)
}

func generateTestL3Rules(rulesCtxt rawL3RuleTestCtxt, orig, ipv4, ipv6 bool) []testL3Rule {
	var testTable []testL3Rule
	var decisions []ruleTest

	if !orig {
		decisions = rulesCtxt.rules[:2]
	}

	for _, r := range decisions {
		for _, id := range rulesCtxt.ids {
			for _, sport := range rulesCtxt.srcports {
				for _, dport := range rulesCtxt.dstports {
					if id.rawid == "ICMP" && (sport.rawport != "ANY" || dport.rawport != "ANY") {
						// Special case for ICMP rule: both source port and destination port should be ANY
						continue
					}
					if ipv4 {
						// Generate Ipv4 Rules
						for _, src4 := range rulesCtxt.srcs4 {
							for _, dst4 := range rulesCtxt.dsts4 {
								ruleWant := l3Rules4{
									OutputNumber: r.gtrule,
									SrcAddr:      src4.gtAddr4.addr,
									DstAddr:      dst4.gtAddr4.addr,
									SrcMask:      src4.gtAddr4.mask,
									DstMask:      dst4.gtAddr4.mask,
									L4: l4Rules{
										IDMask:     uint8(id.gtID.idmsk),
										ID:         uint8(id.gtID.id),
										valid:      sport.gtPort.valid || dport.gtPort.valid,
										SrcPortMin: sport.gtPort.min,
										SrcPortMax: sport.gtPort.max,
										DstPortMin: dport.gtPort.min,
										DstPortMax: dport.gtPort.max,
									},
								}

								rule := rawL3Rules{
									L3Rules: []rawL3Rule{
										{
											OutputNumber: r.rawrule,
											SrcAddr:      src4.rawaddr4,
											DstAddr:      dst4.rawaddr4,
											ID:           id.rawid,
											SrcPort:      sport.rawport,
											DstPort:      dport.rawport,
										},
									},
								}
								testTable = append(testTable, testL3Rule{raw: rule, want4: ruleWant})
							}
						}
					}
					if ipv6 {
						// Generate IPv6 rules
						for _, src6 := range rulesCtxt.srcs6 {
							for _, dst6 := range rulesCtxt.dsts6 {
								ruleWant := l3Rules6{
									OutputNumber: r.gtrule,
									SrcAddr:      src6.gtAddr6.addr,
									DstAddr:      dst6.gtAddr6.addr,
									SrcMask:      src6.gtAddr6.mask,
									DstMask:      dst6.gtAddr6.mask,
									L4: l4Rules{
										IDMask:     uint8(id.gtID.idmsk),
										ID:         uint8(id.gtID.id),
										valid:      sport.gtPort.valid || dport.gtPort.valid,
										SrcPortMin: sport.gtPort.min,
										SrcPortMax: sport.gtPort.max,
										DstPortMin: dport.gtPort.min,
										DstPortMax: dport.gtPort.max,
									},
								}
								rule := rawL3Rules{
									L3Rules: []rawL3Rule{
										{
											OutputNumber: r.rawrule,
											SrcAddr:      src6.rawaddr6,
											DstAddr:      dst6.rawaddr6,
											ID:           id.rawid,
											SrcPort:      sport.rawport,
											DstPort:      dport.rawport,
										},
									},
								}
								testTable = append(testTable, testL3Rule{raw: rule, want6: ruleWant})
							}
						}
					}
				}
			}
		}
	}
	return testTable
}

// Function to test L3 rules parser for JSON format
// L3 rules generated, written to JSON format, then parsed
func TestGetL3ACLFromJSON(t *testing.T) {
	// Generate IPv4 rules
	testTable4 := generateTestL3Rules(rulesL3Ctxt, false, true, false)

	tmpdir := createTmpDir("tmpGetL3ACLFromJSONConfigs")

	for _, rule := range testTable4 {
		nice, _ := json.Marshal(rule.raw)
		tmpfile := createTmpFile(tmpdir, "ipv4_tmp_test.json")
		if _, err := tmpfile.WriteString(string(nice)); err != nil {
			log.Fatal(err)
		}

		ruleGot, err := GetL3ACLFromJSON(tmpfile.Name())
		if err != nil {
			t.Errorf(" GetL3ACLFromJSON returned error %s\n\n", err)
			t.FailNow()
		}

		if !reflect.DeepEqual(ruleGot.ip4[0], rule.want4) {
			t.Errorf("Incorrect parse L3 ipv4 rules:\ngot: %+v \nwant: %+v\n L4 rules: \ngot: %+v \nwant: %+v\n\n",
				ruleGot.ip4[0], rule.want4, ruleGot.ip4[0].L4, rule.want4.L4)
			t.Errorf("Test JSON file %s\n\n", tmpfile.Name())
			t.FailNow()
		}

		closeAndRemove(tmpfile)
	}

	// Generate IPv6 rules
	testTable6 := generateTestL3Rules(rulesL3Ctxt, false, false, true)

	for _, rule := range testTable6 {
		nice, _ := json.Marshal(rule.raw)
		tmpfile := createTmpFile(tmpdir, "ipv6_tmp_test.json")
		if _, err := tmpfile.WriteString(string(nice)); err != nil {
			log.Fatal(err)
		}

		ruleGot, err := GetL3ACLFromJSON(tmpfile.Name())
		if err != nil {
			t.Errorf("GetL3ACLFromJSON returned error %s\n\n", err)
			t.FailNow()
		}

		if !reflect.DeepEqual(ruleGot.ip6[0], rule.want6) {
			t.Errorf("Incorrect parse L3 ipv6 rules:\ngot: %+v \nwant: %+v\n L4 rules: \ngot: %+v \nwant: %+v\n\n",
				ruleGot.ip6[0], rule.want6, ruleGot.ip6[0].L4, rule.want6.L4)
			t.Errorf("Test JSON file %s\n\n", tmpfile.Name())
			t.FailNow()
		}
		closeAndRemove(tmpfile)
	}
	removeIfEmpty(tmpdir)
}

// Function to test L3 rules parser for ORIG format
// L3 rules generated, written to ORIG format, then parsed
func TestGetL3ACLFromORIG(t *testing.T) {
	// Generate IPv4 rules
	testTable4 := generateTestL3Rules(rulesL3Ctxt, true, true, false)

	tmpdir := createTmpDir("tmpGetL3ACLFromORIGConfigs")

	for _, rule := range testTable4 {
		// Create and parse ORIG file
		headerORIG := "# Source address, Destination address, L4 protocol ID, Source port, Destination port, Output port\n"
		r := rule.raw.L3Rules[0]
		ruleORIG := fmt.Sprintf("%s %s %s %s %s %s", r.SrcAddr, r.DstAddr, r.ID, r.SrcPort, r.DstPort, r.OutputNumber)

		tmpfile := createTmpFile(tmpdir, "ipv4_tmp_test.orig")
		if _, err := tmpfile.WriteString(headerORIG + ruleORIG); err != nil {
			log.Fatal(err)
		}

		ruleGot, err := GetL3ACLFromORIG(tmpfile.Name())
		if err != nil {
			t.Errorf("GetL3ACLFromORIG returned error %s\n\n", err)
			t.FailNow()
		}

		if !reflect.DeepEqual(ruleGot.ip4[0], rule.want4) {
			t.Errorf("Incorrect parse L3 ipv4 rules from ORIG:\ngot: %+v \nwant: %+v\n L4 rules: \ngot: %+v \nwant: %+v\n\n",
				ruleGot.ip4[0], rule.want4, ruleGot.ip4[0].L4, rule.want4.L4)
			t.Errorf("Test ORIG file %s\n\n", tmpfile.Name())
			t.FailNow()
		}

		closeAndRemove(tmpfile)
	}

	// Generate IPv6 rules
	testTable6 := generateTestL3Rules(rulesL3Ctxt, true, false, true)

	for _, rule := range testTable6 {
		// Create and parse ORIG file
		headerORIG := "# Source address, Destination address, L4 protocol ID, Source port, Destination port, Output port\n"
		r := rule.raw.L3Rules[0]
		ruleORIG := fmt.Sprintf("%s %s %s %s %s %s", r.SrcAddr, r.DstAddr, r.ID, r.SrcPort, r.DstPort, r.OutputNumber)

		tmpfile := createTmpFile(tmpdir, "ipv6_tmp_test.orig")
		if _, err := tmpfile.WriteString(headerORIG + ruleORIG); err != nil {
			log.Fatal(err)
		}

		ruleGot, err := GetL3ACLFromORIG(tmpfile.Name())
		if err != nil {
			t.Errorf("GetL3ACLFromORIG returned error %s\n\n", err)
			t.FailNow()
		}

		if !reflect.DeepEqual(ruleGot.ip6[0], rule.want6) {
			t.Errorf("Incorrect parse L3 ipv6 rules from ORIG:\ngot: %+v \nwant: %+v\n L4 rules: \ngot: %+v \nwant: %+v\n\n",
				ruleGot.ip6[0], rule.want6, ruleGot.ip6[0].L4, rule.want6.L4)
			t.Errorf("Test ORIG file %s\n\n", tmpfile.Name())
			t.FailNow()
		}
		closeAndRemove(tmpfile)
	}
	removeIfEmpty(tmpdir)
}

// Tests for l4ACL internal function on TCP packet
// This functions is called only inside l3ACL, so we need to test it standalone first
func TestInternal_l4ACL_packetIPv4_TCP(t *testing.T) {
	pkt := getIPv4TCPTestPacket()

	// Generate rules by combining these given field values:
	rulesCtxt := l4Context{
		srcRange: []portRange{
			{min: 0, max: 65535, ok: true},
			{min: 1234, max: 1234, ok: true},
			{min: 1233, max: 1299, ok: true},
			{min: 0, max: 0, ok: false},
			{min: 2000, max: 2000, ok: false},
		},
		dstRange: []portRange{
			{min: 0, max: 65535, ok: true},
			{min: 5678, max: 5678, ok: true},
			{min: 9999, max: 9999, ok: false},
		},
	}

	for i, srcRange := range rulesCtxt.srcRange {
		for j, dstRange := range rulesCtxt.dstRange {
			rule := l4Rules{
				SrcPortMin: srcRange.min,
				SrcPortMax: srcRange.max,
				DstPortMin: dstRange.min,
				DstPortMax: dstRange.max,
			}

			got := pkt.l4ACL(&rule)
			want := srcRange.ok && dstRange.ok

			if got != want {
				t.Errorf("Incorrect result for rule (%d, %d):\n got: %t\n want: %t\n Rule:%s", i, j, got, want, rule)
			}
		}
	}
}

func (rule l4Rules) String() string {
	return fmt.Sprintf("srcMin: %d, srcMax: %d, dstMin: %d, dstMax: %d, ID=%x, IDMask=%x, valid=%t", rule.SrcPortMin, rule.SrcPortMax, rule.DstPortMin, rule.DstPortMax, rule.ID, rule.IDMask, rule.valid)
}

func (rule l3Rules4) String() string {
	h0 := "Ipv4 Rule:"
	h1 := fmt.Sprintf("outputNumber: %d, srcAddr: %x, srcMask: %x, dstAddr: %x, dstMask: %x", rule.OutputNumber, rule.SrcAddr, rule.SrcMask, rule.DstAddr, rule.DstMask)
	return h0 + h1
}

func (rule l3Rules6) String() string {
	h0 := "Ipv6 Rule:"
	h1 := fmt.Sprintf("outputNumber: %d, \nsrcAddr: %16x, \nsrcMask: %16x, \ndstAddr: %16x, \ndstMask: %16x", rule.OutputNumber, rule.SrcAddr, rule.SrcMask, rule.DstAddr, rule.DstMask)
	return h0 + h1
}

// Tests for l3ACL (without call to l4ACL)
func TestInternal_l3ACL_packetIPv4_TCP(t *testing.T) {
	pkt := getIPv4TCPTestPacket()

	// Generate l3 rules for ipv4 by combining these given field values:
	rulesl3Ctxt4 := l3Context4{
		OutputNumber: []uint{0, 1, 10, 65535},
		srcAddrMsk: []Addr4Mask{
			{addr: 0x0100007f, msk: 0xffffffff, ok: true},  // 127.0.0.1
			{addr: 0x00000000, msk: 0x00000000, ok: true},  // ANY
			{addr: 0x0200007f, msk: 0x00ffffff, ok: true},  // 127.0.0.0
			{addr: 0x0200007f, msk: 0xffffffff, ok: false}, // 127.0.0.2
		},
		dstAddrMsk: []Addr4Mask{
			{addr: 0x05090980, msk: 0xffffffff, ok: true},  // 128.9.9.5
			{addr: 0x00000000, msk: 0x00000000, ok: true},  // ANY
			{addr: 0x0200007f, msk: 0x00ffffff, ok: false}, // 127.0.0.2
			{addr: 0x05050980, msk: 0x0000ffff, ok: true},  // 128.9.0.0
		},
	}

	// Generate L3 ipv4 rules
	for l, outNum := range rulesl3Ctxt4.OutputNumber {
		for m, srcAddrMsk := range rulesl3Ctxt4.srcAddrMsk {
			for n, dstAddrMsk := range rulesl3Ctxt4.dstAddrMsk {
				l3rule4 := []l3Rules4{
					{
						OutputNumber: outNum,
						SrcAddr:      srcAddrMsk.addr,
						DstAddr:      dstAddrMsk.addr,
						SrcMask:      srcAddrMsk.msk,
						DstMask:      dstAddrMsk.msk,
					},
				}

				l3rule := L3Rules{
					ip4: l3rule4,
					ip6: nil,
				}

				got := pkt.l3ACL(&l3rule)
				var want uint
				if srcAddrMsk.ok && dstAddrMsk.ok { // check only l3-related fields here
					want = outNum
				} else {
					want = 0
				}

				if got != want {
					t.Errorf("Incorrect result for rule (%d, %d, %d):\n got: %d\n want: %d\n %s", l, m, n, got, want, l3rule.ip4[0])
				}
			}
		}
	}
}

// Tests for l3ACL (with call to l4ACL) for IPv4/TCP packet
func TestInternal_l3ACL_l4ACL_packetIPv4_TCP(t *testing.T) {
	pkt := getIPv4TCPTestPacket()

	// l4 rules will be generated by combining these given field values:
	rulesl4Ctxt := l4Context{
		idMsk: []IDMask{
			{id: 0, mask: 0, ok: true},
			{id: 6, mask: 0xff, ok: true},
			{id: 17, mask: 0xff, ok: false},
		},
		srcRange: []portRange{
			{min: 0, max: 65535, valid: false, ok: true},
			{min: 13, max: 17, valid: true, ok: false},
			{min: 1234, max: 1234, valid: true, ok: true},
			{min: 1233, max: 1299, valid: true, ok: true},
			{min: 0, max: 0, valid: true, ok: false},
		},
		dstRange: []portRange{
			{min: 0, max: 65535, valid: false, ok: true},
			{min: 9999, max: 9999, valid: true, ok: false},
			{min: 5678, max: 5678, valid: true, ok: true},
		},
	}

	// l3 rules for IPv4 will be generated by combining these given field values:
	rulesl3Ctxt4 := l3Context4{
		OutputNumber: []uint{0, 1, 65535},
		srcAddrMsk: []Addr4Mask{
			{addr: 0x0100007f, msk: 0xffffffff, ok: true},  // 127.0.0.1
			{addr: 0x00000000, msk: 0x00000000, ok: true},  // ANY
			{addr: 0x0200007f, msk: 0x00ffffff, ok: true},  // 127.0.0.0
			{addr: 0x0200007f, msk: 0xffffffff, ok: false}, // 127.0.0.2
		},
		dstAddrMsk: []Addr4Mask{
			{addr: 0x05090980, msk: 0xffffffff, ok: true},  // 128.9.9.5
			{addr: 0x00000000, msk: 0x00000000, ok: true},  // ANY
			{addr: 0x0200007f, msk: 0x00ffffff, ok: false}, // 127.0.0.2
			{addr: 0x05050980, msk: 0x0000ffff, ok: true},  // 128.9.0.0
		},
	}

	// Generate L4 rules
	for i, idMsk := range rulesl4Ctxt.idMsk {
		for j, srcRange := range rulesl4Ctxt.srcRange {
			for k, dstRange := range rulesl4Ctxt.dstRange {
				l4rule := l4Rules{
					ID:         idMsk.id,
					IDMask:     idMsk.mask,
					valid:      srcRange.valid || dstRange.valid,
					SrcPortMin: srcRange.min,
					SrcPortMax: srcRange.max,
					DstPortMin: dstRange.min,
					DstPortMax: dstRange.max,
				}
				// Generate L3 rules IPv4
				for l, outNum := range rulesl3Ctxt4.OutputNumber {
					for m, srcAddrMsk := range rulesl3Ctxt4.srcAddrMsk {
						for n, dstAddrMsk := range rulesl3Ctxt4.dstAddrMsk {
							l3rule4 := []l3Rules4{
								{
									OutputNumber: outNum,
									SrcAddr:      srcAddrMsk.addr,
									DstAddr:      dstAddrMsk.addr,
									SrcMask:      srcAddrMsk.msk,
									DstMask:      dstAddrMsk.msk,
									L4:           l4rule,
								},
							}

							l3rule := L3Rules{
								ip4: l3rule4,
								ip6: nil,
							}

							got := pkt.l3ACL(&l3rule)
							var want uint
							if idMsk.ok && srcRange.ok && dstRange.ok && srcAddrMsk.ok && dstAddrMsk.ok {
								want = outNum
							} else {
								want = 0
							}

							if got != want {
								t.Errorf("Incorrect result for rule (%d, %d, %d, %d, %d, %d):\n got: %d\n want: %d\n %s", i, j, k, l, m, n, got, want, l3rule.ip4[0])
							}
						}
					}
				}
			}
		}
	}
}

// Tests for l3ACL (with call to l4ACL) for IPv6/TCP packet
func TestInternal_l3ACL_l4ACL_packetIPv6_TCP(t *testing.T) {
	pkt := getIPv6TCPTestPacket()

	// l4 rules will be generated by combining these given field values:
	rulesl4Ctxt := l4Context{
		idMsk: []IDMask{
			{id: 0, mask: 0, ok: true},
			{id: 6, mask: 0xff, ok: true},
			{id: 17, mask: 0xff, ok: false},
		},
		srcRange: []portRange{
			{min: 0, max: 65535, valid: false, ok: true},
			{min: 13, max: 17, valid: true, ok: false},
			{min: 1234, max: 1234, valid: true, ok: true},
			{min: 1233, max: 1299, valid: true, ok: true},
			{min: 0, max: 0, valid: true, ok: false},
		},
		dstRange: []portRange{
			{min: 0, max: 65535, valid: false, ok: true},
			{min: 9999, max: 9999, valid: true, ok: false},
			{min: 5678, max: 5678, valid: true, ok: true},
		},
	}

	// l3 rules for IPv4 will be generated by combining these given field values:
	rulesl3Ctxt6 := l3Context6{
		OutputNumber: []uint{0, 1, 65535},
		srcAddrMsk: []Addr6Mask{
			{
				addr: [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				msk:  [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb, 0xbb},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff},
				ok:   false,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0xdd},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
		},
		dstAddrMsk: []Addr6Mask{
			{
				addr: [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				msk:  [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb, 0xbb},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff},
				ok:   false,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0xdd},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
		},
	}

	// Generate L4 rules
	for i, idMsk := range rulesl4Ctxt.idMsk {
		for j, srcRange := range rulesl4Ctxt.srcRange {
			for k, dstRange := range rulesl4Ctxt.dstRange {
				l4rule := l4Rules{
					ID:         idMsk.id,
					IDMask:     idMsk.mask,
					valid:      srcRange.valid || dstRange.valid,
					SrcPortMin: srcRange.min,
					SrcPortMax: srcRange.max,
					DstPortMin: dstRange.min,
					DstPortMax: dstRange.max,
				}
				// Generate L3 rules IPv6
				for l, outNum := range rulesl3Ctxt6.OutputNumber {
					for m, srcAddrMsk := range rulesl3Ctxt6.srcAddrMsk {
						for n, dstAddrMsk := range rulesl3Ctxt6.dstAddrMsk {
							l3rule6 := []l3Rules6{
								{
									OutputNumber: outNum,
									SrcAddr:      srcAddrMsk.addr,
									DstAddr:      dstAddrMsk.addr,
									SrcMask:      srcAddrMsk.msk,
									DstMask:      dstAddrMsk.msk,
									L4:           l4rule,
								},
							}

							l3rule := L3Rules{
								ip4: nil,
								ip6: l3rule6,
							}

							got := pkt.l3ACL(&l3rule)
							var want uint
							if idMsk.ok && srcRange.ok && dstRange.ok && srcAddrMsk.ok && dstAddrMsk.ok {
								want = outNum
							} else {
								want = 0
							}

							if got != want {
								t.Errorf("Incorrect result for rule (%d, %d, %d, %d, %d, %d):\n got: %d\n want: %d\n %s", i, j, k, l, m, n, got, want, l3rule.ip6[0])
							}
						}
					}
				}
			}
		}
	}
}

// Tests for l3ACL (with call to l4ACL) for IPv6/UDP packet
func TestInternal_l3ACL_l4ACL_packetIPv6_UDP(t *testing.T) {
	pkt := getIPv6UDPTestPacket()

	// l4 rules will be generated by combining these given field values:
	rulesl4Ctxt := l4Context{
		idMsk: []IDMask{
			{id: 0, mask: 0, ok: true},
			{id: 6, mask: 0xff, ok: false},
			{id: 17, mask: 0xff, ok: true},
		},
		srcRange: []portRange{
			{min: 0, max: 65535, valid: false, ok: true},
			{min: 13, max: 17, valid: true, ok: false},
			{min: 1234, max: 1234, valid: true, ok: true},
			{min: 1233, max: 1299, valid: true, ok: true},
			{min: 0, max: 0, valid: true, ok: false},
		},
		dstRange: []portRange{
			{min: 0, max: 65535, valid: false, ok: true},
			{min: 9999, max: 9999, valid: true, ok: false},
			{min: 5678, max: 5678, valid: true, ok: true},
		},
	}

	// l3 rules for IPv4 will be generated by combining these given field values:
	rulesl3Ctxt6 := l3Context6{
		OutputNumber: []uint{0, 1, 65535},
		srcAddrMsk: []Addr6Mask{
			{
				addr: [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				msk:  [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb, 0xbb},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff},
				ok:   false,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0xdd},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
		},
		dstAddrMsk: []Addr6Mask{
			{
				addr: [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				msk:  [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb, 0xbb},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff},
				ok:   false,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0xdd},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
		},
	}

	// Generate L4 rules
	for i, idMsk := range rulesl4Ctxt.idMsk {
		for j, srcRange := range rulesl4Ctxt.srcRange {
			for k, dstRange := range rulesl4Ctxt.dstRange {
				l4rule := l4Rules{
					ID:         idMsk.id,
					IDMask:     idMsk.mask,
					valid:      srcRange.valid || dstRange.valid,
					SrcPortMin: srcRange.min,
					SrcPortMax: srcRange.max,
					DstPortMin: dstRange.min,
					DstPortMax: dstRange.max,
				}
				// Generate L3 rules IPv6
				for l, outNum := range rulesl3Ctxt6.OutputNumber {
					for m, srcAddrMsk := range rulesl3Ctxt6.srcAddrMsk {
						for n, dstAddrMsk := range rulesl3Ctxt6.dstAddrMsk {
							l3rule6 := []l3Rules6{
								{
									OutputNumber: outNum,
									SrcAddr:      srcAddrMsk.addr,
									DstAddr:      dstAddrMsk.addr,
									SrcMask:      srcAddrMsk.msk,
									DstMask:      dstAddrMsk.msk,
									L4:           l4rule,
								},
							}

							l3rule := L3Rules{
								ip4: nil,
								ip6: l3rule6,
							}

							got := pkt.l3ACL(&l3rule)
							var want uint
							if idMsk.ok && srcRange.ok && dstRange.ok && srcAddrMsk.ok && dstAddrMsk.ok {
								want = outNum
							} else {
								want = 0
							}

							if got != want {
								t.Errorf("Incorrect result for rule (%d, %d, %d, %d, %d, %d):\n got: %d\n want: %d\n %s", i, j, k, l, m, n, got, want, l3rule.ip6[0])
							}
						}
					}
				}
			}
		}
	}
}

func TestInternal_l3ACL_l4ACL_packetIPv4_ICMP(t *testing.T) {
	pkt := getIPv4ICMPTestPacket()

	// l4 rules will be generated by combining these given field values:
	rulesl4Ctxt := l4Context{
		idMsk: []IDMask{
			{id: 0, mask: 0, ok: true},
			{id: 6, mask: 0xff, ok: false},
			{id: 17, mask: 0xff, ok: false},
			{id: 1, mask: 0xff, ok: true}, // ICMP
		},
		srcRange: []portRange{
			{min: 0, max: 65535, valid: false, ok: true},
			{min: 13, max: 17, valid: true, ok: false},
			{min: 1234, max: 1234, valid: true, ok: false},
		},
		dstRange: []portRange{
			{min: 0, max: 65535, valid: false, ok: true},
			{min: 9999, max: 9999, valid: true, ok: false},
			{min: 5678, max: 5678, valid: true, ok: false},
		},
	}

	// l3 rules for IPv4 will be generated by combining these given field values:
	rulesl3Ctxt4 := l3Context4{
		OutputNumber: []uint{0, 1, 65535},
		srcAddrMsk: []Addr4Mask{
			{addr: 0x0100007f, msk: 0xffffffff, ok: true},  // 127.0.0.1
			{addr: 0x00000000, msk: 0x00000000, ok: true},  // ANY
			{addr: 0x0200007f, msk: 0x00ffffff, ok: true},  // 127.0.0.0
			{addr: 0x0200007f, msk: 0xffffffff, ok: false}, // 127.0.0.2
		},
		dstAddrMsk: []Addr4Mask{
			{addr: 0x05090980, msk: 0xffffffff, ok: true},  // 128.9.9.5
			{addr: 0x00000000, msk: 0x00000000, ok: true},  // ANY
			{addr: 0x0200007f, msk: 0x00ffffff, ok: false}, // 127.0.0.2
			{addr: 0x05050980, msk: 0x0000ffff, ok: true},  // 128.9.0.0
		},
	}

	// Generate L4 rules
	for i, idMsk := range rulesl4Ctxt.idMsk {
		for j, srcRange := range rulesl4Ctxt.srcRange {
			for k, dstRange := range rulesl4Ctxt.dstRange {
				l4rule := l4Rules{
					ID:         idMsk.id,
					IDMask:     idMsk.mask,
					valid:      srcRange.valid || dstRange.valid,
					SrcPortMin: srcRange.min,
					SrcPortMax: srcRange.max,
					DstPortMin: dstRange.min,
					DstPortMax: dstRange.max,
				}
				// Generate L3 rules IPv4
				for l, outNum := range rulesl3Ctxt4.OutputNumber {
					for m, srcAddrMsk := range rulesl3Ctxt4.srcAddrMsk {
						for n, dstAddrMsk := range rulesl3Ctxt4.dstAddrMsk {
							l3rule4 := []l3Rules4{
								{
									OutputNumber: outNum,
									SrcAddr:      srcAddrMsk.addr,
									DstAddr:      dstAddrMsk.addr,
									SrcMask:      srcAddrMsk.msk,
									DstMask:      dstAddrMsk.msk,
									L4:           l4rule,
								},
							}

							l3rule := L3Rules{
								ip4: l3rule4,
								ip6: nil,
							}

							got := pkt.l3ACL(&l3rule)
							var want uint
							if idMsk.ok && srcRange.ok && dstRange.ok && srcAddrMsk.ok && dstAddrMsk.ok {
								want = outNum
							} else {
								want = 0
							}

							if got != want {
								t.Errorf("Incorrect result for rule (%d, %d, %d, %d, %d, %d):\n got: %d\n want: %d\n %s", i, j, k, l, m, n, got, want, l3rule.ip4[0])
							}
						}
					}
				}
			}
		}
	}
}

func TestInternal_l3ACL_l4ACL_packetIPv6_ICMP(t *testing.T) {
	pkt := getIPv6ICMPTestPacket()

	// l4 rules will be generated by combining these given field values:
	rulesl4Ctxt := l4Context{
		idMsk: []IDMask{
			{id: 0, mask: 0, ok: true},
			{id: 6, mask: 0xff, ok: false},
			{id: 17, mask: 0xff, ok: false},
			{id: 1, mask: 0xff, ok: true}, // ICMP
		},
		srcRange: []portRange{
			{min: 0, max: 65535, valid: false, ok: true},
			{min: 13, max: 17, valid: true, ok: false},
			{min: 1234, max: 1234, valid: true, ok: false},
		},
		dstRange: []portRange{
			{min: 0, max: 65535, valid: false, ok: true},
			{min: 9999, max: 9999, valid: true, ok: false},
			{min: 5678, max: 5678, valid: true, ok: false},
		},
	}

	// l3 rules for IPv4 will be generated by combining these given field values:
	rulesl3Ctxt6 := l3Context6{
		OutputNumber: []uint{0, 1, 65535},
		srcAddrMsk: []Addr6Mask{
			{
				addr: [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				msk:  [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb, 0xbb},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff},
				ok:   false,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0xdd},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
		},
		dstAddrMsk: []Addr6Mask{
			{
				addr: [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				msk:  [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb, 0xbb},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff},
				ok:   false,
			},
			{
				addr: [16]uint8{0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0xdd},
				msk:  [16]uint8{0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				ok:   true,
			},
		},
	}

	// Generate L4 rules
	for i, idMsk := range rulesl4Ctxt.idMsk {
		for j, srcRange := range rulesl4Ctxt.srcRange {
			for k, dstRange := range rulesl4Ctxt.dstRange {
				l4rule := l4Rules{
					ID:         idMsk.id,
					IDMask:     idMsk.mask,
					valid:      srcRange.valid || dstRange.valid,
					SrcPortMin: srcRange.min,
					SrcPortMax: srcRange.max,
					DstPortMin: dstRange.min,
					DstPortMax: dstRange.max,
				}
				// Generate L3 rules IPv6
				for l, outNum := range rulesl3Ctxt6.OutputNumber {
					for m, srcAddrMsk := range rulesl3Ctxt6.srcAddrMsk {
						for n, dstAddrMsk := range rulesl3Ctxt6.dstAddrMsk {
							l3rule6 := []l3Rules6{
								{
									OutputNumber: outNum,
									SrcAddr:      srcAddrMsk.addr,
									DstAddr:      dstAddrMsk.addr,
									SrcMask:      srcAddrMsk.msk,
									DstMask:      dstAddrMsk.msk,
									L4:           l4rule,
								},
							}

							l3rule := L3Rules{
								ip4: nil,
								ip6: l3rule6,
							}

							got := pkt.l3ACL(&l3rule)
							var want uint
							if idMsk.ok && srcRange.ok && dstRange.ok && srcAddrMsk.ok && dstAddrMsk.ok {
								want = outNum
							} else {
								want = 0
							}

							if got != want {
								t.Errorf("Incorrect result for rule (%d, %d, %d, %d, %d, %d):\n got: %d\n want: %d\n %s", i, j, k, l, m, n, got, want, l3rule.ip6[0])
							}
						}
					}
				}
			}
		}
	}
}

// Tests for l2ACL
func TestInternal_l2ACL_packetIPv4(t *testing.T) {
	// One of IPv4 test packets
	pkt := getIPv4UDPTestPacket()

	rulesCtxt := l2Context{
		OutputNumber: []uint{
			0,
			1,
			65535,
		},
		idMsk: []IDMask16{
			{id: 0, mask: 0, ok: true},
			{id: 0x0800, mask: 0xffff, ok: true}, // IPv4
			{id: 0x86dd, mask: 0xffff, ok: false},
			{id: 0x0806, mask: 0xffff, ok: false},
		},
		srcMac: []MacAddr{
			{addr: [6]uint8{0, 0, 0, 0, 0, 0}, addrNotAny: false, ok: true},
			{addr: [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51}, addrNotAny: true, ok: true}, // SAddr = "01:11:21:31:41:51"
			{addr: [6]uint8{0, 0x55, 0x55, 0x55, 0x55, 0}, addrNotAny: true, ok: false},
		},
		dstMac: []MacAddr{
			{addr: [6]uint8{0, 0, 0, 0, 0, 0}, addrNotAny: false, ok: true},
			{addr: [6]uint8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, addrNotAny: true, ok: true}, // DAddr = "00:11:22:33:44:55"
			{addr: [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51}, addrNotAny: true, ok: false},
		},
	}

	// Generate L2 rules
	for k, outNum := range rulesCtxt.OutputNumber {
		for l, idMsk := range rulesCtxt.idMsk {
			for m, src := range rulesCtxt.srcMac {
				for n, dst := range rulesCtxt.dstMac {
					ethRule := []l2Rules{
						{
							OutputNumber: outNum,
							SAddrNotAny:  src.addrNotAny,
							DAddrNotAny:  dst.addrNotAny,
							SAddr:        src.addr,
							DAddr:        dst.addr,
							IDMask:       idMsk.mask,
							ID:           idMsk.id,
						},
					}

					l2rule := L2Rules{
						eth: ethRule,
					}

					got := pkt.l2ACL(&l2rule)
					var want uint
					if idMsk.ok && src.ok && dst.ok {
						want = outNum
					} else {
						want = 0
					}

					if got != want {
						t.Errorf("Incorrect result for rule (%d, %d, %d, %d):\n got: %d\n want: %d\n %+v", k, l, m, n, got, want, l2rule.eth[0])
					}
				}
			}
		}
	}
}

func TestInternal_l2ACL_packetARP(t *testing.T) {
	pkt := getARPRequestTestPacket()

	rulesCtxt := l2Context{
		OutputNumber: []uint{
			0,
			1,
			65535,
		},
		idMsk: []IDMask16{
			{id: 0, mask: 0, ok: true},
			{id: 0x0800, mask: 0xffff, ok: false},
			{id: 0x86dd, mask: 0xffff, ok: false},
			{id: 0x0806, mask: 0xffff, ok: true}, // ARP
		},
		srcMac: []MacAddr{
			{addr: [6]uint8{0, 0, 0, 0, 0, 0}, addrNotAny: false, ok: true},
			{addr: [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51}, addrNotAny: true, ok: true},
			{addr: [6]uint8{0x0, 0x11, 0x22, 0x33, 0x44, 0x55}, addrNotAny: true, ok: false},
		},
		dstMac: []MacAddr{
			{addr: [6]uint8{0, 0, 0, 0, 0, 0}, addrNotAny: false, ok: true},
			{addr: [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, addrNotAny: true, ok: true},
			{addr: [6]uint8{0x01, 0x11, 0x21, 0x31, 0x41, 0x51}, addrNotAny: true, ok: false},
		},
	}

	// Generate L2 rules
	for k, outNum := range rulesCtxt.OutputNumber {
		for l, idMsk := range rulesCtxt.idMsk {
			for m, src := range rulesCtxt.srcMac {
				for n, dst := range rulesCtxt.dstMac {
					ethRule := []l2Rules{
						{
							OutputNumber: outNum,
							SAddrNotAny:  src.addrNotAny,
							DAddrNotAny:  dst.addrNotAny,
							SAddr:        src.addr,
							DAddr:        dst.addr,
							IDMask:       idMsk.mask,
							ID:           idMsk.id,
						},
					}

					l2rule := L2Rules{
						eth: ethRule,
					}

					got := pkt.l2ACL(&l2rule)
					var want uint
					if idMsk.ok && src.ok && dst.ok {
						want = outNum
					} else {
						want = 0
					}

					if got != want {
						t.Errorf("Incorrect result for rule (%d, %d, %d, %d):\n got: %d\n want: %d\n %+v", k, l, m, n, got, want, l2rule.eth[0])
					}
				}
			}
		}
	}
}

func createTmpDir(prefix string) string {
	name, err := ioutil.TempDir(".", prefix)
	if err != nil {
		log.Fatal(err)
	}
	return name
}

func createTmpFile(dname, prefix string) *os.File {
	f, err := ioutil.TempFile(dname, prefix)
	if err != nil {
		log.Fatal(err)
	}
	return f
}

func closeAndRemove(tmpfile *os.File) {
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}
	os.Remove(tmpfile.Name())
}

func removeIfEmpty(tmpdir string) {
	files, _ := ioutil.ReadDir(tmpdir)
	if len(files) == 0 {
		os.Remove(tmpdir)
	}
}

// Helper structs for parsing
type rawL2RuleTestCtxt struct {
	rules []ruleTest
	srcs  []macAddrTest
	dsts  []macAddrTest
	ids   []idTest
}

type macAddrTest struct {
	rawaddr string
	gtMacAddr
}

type gtMacAddr struct {
	addr       [6]uint8
	addrNotAny bool
}

type rawL3RuleTestCtxt struct {
	srcs4 []Addr4Test
	dsts4 []Addr4Test

	srcs6 []Addr6Test
	dsts6 []Addr6Test

	ids      []idTest
	srcports []portTest
	dstports []portTest
	rules    []ruleTest // OutputNumber
}

type Addr4Test struct {
	rawaddr4 string
	gtAddr4
}

type Addr6Test struct {
	rawaddr6 string
	gtAddr6
}

type gtAddr4 struct {
	addr uint32
	mask uint32
}

type gtAddr6 struct {
	addr [16]uint8
	mask [16]uint8
}

type portTest struct {
	rawport string
	gtPort
}

type gtPort struct {
	min   uint16
	max   uint16
	valid bool
}

type ruleTest struct {
	rawrule string
	gtrule  uint
}

type idTest struct {
	rawid string
	gtID
}

type gtID struct {
	id    uint16
	idmsk uint16
}

// Helper structs for rules checking tests
type portRange struct {
	min   uint16
	max   uint16
	valid bool // Is L4 rule active
	ok    bool // does test packet port suit to this range
}

type l2Context struct {
	OutputNumber []uint
	idMsk        []IDMask16
	srcMac       []MacAddr
	dstMac       []MacAddr
}

type l4Context struct {
	idMsk    []IDMask
	srcRange []portRange
	dstRange []portRange
}

type l3Context4 struct {
	OutputNumber []uint
	srcAddrMsk   []Addr4Mask
	dstAddrMsk   []Addr4Mask
	L4           l4Rules
}

type l3Context6 struct {
	OutputNumber []uint
	srcAddrMsk   []Addr6Mask
	dstAddrMsk   []Addr6Mask
	L4           l4Rules
}

type IDMask struct {
	id   uint8
	mask uint8
	ok   bool
}
type IDMask16 struct {
	id   uint16
	mask uint16
	ok   bool
}

type Addr4Mask struct {
	addr uint32
	msk  uint32
	ok   bool
}

type Addr6Mask struct {
	addr [16]uint8
	msk  [16]uint8
	ok   bool
}

type MacAddr struct {
	addr       [6]uint8
	addrNotAny bool
	ok         bool
}
