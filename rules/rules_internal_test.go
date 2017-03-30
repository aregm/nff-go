// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rules

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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"nfv/low"
	"nfv/packet"
	"os"
	"reflect"
	"testing"
)

func init() {
	argc, argv := low.ParseFlags()
	// burstSize=32, mbufNumber=8191, mbufCacheSize=250
	low.InitDPDK(argc, argv, 32, 8191, 250)
}

// Function to test L2 rules parser
// L2 rules generated, written to json, then parsed
func TestL2RulesReadingGen(t *testing.T) {
	// Data to generate L2 rules
	rulesCtxt := rawL2RuleTestCtxt{
		rules: []ruleTest{ // {rawrule, ground truth rule}
			{"Accept", 1},
			{"Reject", 0},
			{"3", 3},
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
			{"ANY", gtId{0, 0x0000}},
			{"IPv4", gtId{0x0800, 0xffff}},
			{"IPv6", gtId{0x86dd, 0xffff}},
		},
	}

	tmpdir, err := ioutil.TempDir(".", "tmp_TestL2RulesReadingGen_configs")
	if err != nil {
		log.Fatal(err)
	}

	for _, r := range rulesCtxt.rules {
		for _, src := range rulesCtxt.srcs {
			for _, dst := range rulesCtxt.dsts {
				for _, id := range rulesCtxt.ids {

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

					nice, _ := json.Marshal(rule)
					tmpfile, err := ioutil.TempFile(tmpdir, "tmp_test.json")
					if err != nil {
						log.Fatal(err)
					}
					if _, err := tmpfile.WriteString(string(nice)); err != nil {
						log.Fatal(err)
					}

					// Expected result of parsing
					rule_want := l2Rules{
						OutputNumber: r.gtrule,
						DAddrNotAny:  dst.addrNotAny,
						SAddrNotAny:  src.addrNotAny,
						DAddr:        dst.addr,
						SAddr:        src.addr,
						IDMask:       id.idmsk,
						ID:           id.id,
					}

					// Now we can read file, parse l2 rule and compare result with expected
					rule_got := GetL2RulesFromJSON(tmpfile.Name())

					if !reflect.DeepEqual(rule_got.eth[0], rule_want) {
						t.Errorf("Incorrect parse L2 rules")
						t.FailNow()
					}

					if err := tmpfile.Close(); err != nil {
						log.Fatal(err)
					}
					os.Remove(tmpfile.Name()) // remove if test passed
				}
			}
		}
	}

	// If all tests passed (tmpdir is empty), remove tmpdir
	files, _ := ioutil.ReadDir(tmpdir)
	if len(files) == 0 {
		os.Remove(tmpdir)
	}
}

// Function to test L3 rules parser
// This function tests reading from both file formats - JSON and ORIG
func TestL3RulesReadingGen(t *testing.T) {
	// Data to generate L3 rules
	rulesCtxt := rawL3RuleTestCtxt{
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
			{"ANY", gtId{0, 0x0000}},
			{"TCP", gtId{0x06, 0xff}},
			{"UDP", gtId{0x11, 0xff}},
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
		},
	}

	tmpdir, err := ioutil.TempDir(".", "tmp_TestL3RulesReadingGen_configs")
	if err != nil {
		log.Fatal(err)
	}

	for _, r := range rulesCtxt.rules {
		for _, id := range rulesCtxt.ids {
			for _, sport := range rulesCtxt.srcports {
				for _, dport := range rulesCtxt.dstports {
					///////// Generate Ipv4 Rules /////////
					for _, src4 := range rulesCtxt.srcs4 {
						for _, dst4 := range rulesCtxt.dsts4 {
							// Form expected result of parsing
							rule_want := l3Rules4{
								OutputNumber: r.gtrule,
								SrcAddr:      src4.gtAddr4.addr,
								DstAddr:      dst4.gtAddr4.addr,
								SrcMask:      src4.gtAddr4.mask,
								DstMask:      dst4.gtAddr4.mask,
								L4: l4Rules{
									IDMask:     uint8(id.gtId.idmsk),
									ID:         uint8(id.gtId.id),
									valid:      sport.gtPort.valid || dport.gtPort.valid,
									SrcPortMin: sport.gtPort.min,
									SrcPortMax: sport.gtPort.max,
									DstPortMin: dport.gtPort.min,
									DstPortMax: dport.gtPort.max,
								},
							}

							/***** Create and parse JSON file for IPv4 *****/
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

							nice, _ := json.Marshal(rule)
							tmpfile, err := ioutil.TempFile(tmpdir, "ipv4_tmp_test.json")
							if err != nil {
								log.Fatal(err)
							}
							if _, err := tmpfile.WriteString(string(nice)); err != nil {
								log.Fatal(err)
							}

							// Now we can read file, parse l2 rule and compare result with expected.
							rule_got := GetL3RulesFromJSON(tmpfile.Name())

							if !reflect.DeepEqual(rule_got.ip4[0], rule_want) {
								t.Errorf("Incorrect parse L3 ipv4 rules:\ngot: %+v \nwant: %+v\n L4 rules: \ngot: %+v \nwant: %+v\n\n",
									rule_got.ip4[0], rule_want, rule_got.ip4[0].L4, rule_want.L4)
								t.Errorf("Test JSON file %s\n\n", tmpfile.Name())
								t.FailNow()
							}

							if err := tmpfile.Close(); err != nil {
								log.Fatal(err)
							}
							os.Remove(tmpfile.Name()) // remove if test passed

							/***** Create and parse ORIG file for IPv4 *****/
							headerORIG := "# Source address, Destination address, L4 protocol ID, Source port, Destination port, Output port\n"
							ruleORIG := fmt.Sprintf("%s %s %s %s %s %s",
								src4.rawaddr4, dst4.rawaddr4, id.rawid, sport.rawport, dport.rawport, r.rawrule)

							tmpfile, err = ioutil.TempFile(tmpdir, "ipv4_tmp_test.orig")
							if err != nil {
								log.Fatal(err)
							}
							if _, err = tmpfile.WriteString(headerORIG + ruleORIG); err != nil {
								log.Fatal(err)
							}

							// Now we can read file, parse l2 rule and compare result with expected.
							rule_got = GetL3RulesFromORIG(tmpfile.Name())

							if !reflect.DeepEqual(rule_got.ip4[0], rule_want) {
								t.Errorf("Incorrect parse L3 ipv4 rules from ORIG:\ngot: %+v \nwant: %+v\n L4 rules: \ngot: %+v \nwant: %+v\n\n",
									rule_got.ip4[0], rule_want, rule_got.ip4[0].L4, rule_want.L4)
								t.Errorf("Test ORIG file %s\n\n", tmpfile.Name())
								t.FailNow()
							}

							if err = tmpfile.Close(); err != nil {
								log.Fatal(err)
							}
							os.Remove(tmpfile.Name()) // remove if test passed
						}
					}

					///////// Generate Ipv6 Rules /////////
					for _, src6 := range rulesCtxt.srcs6 {
						for _, dst6 := range rulesCtxt.dsts6 {
							// Create and parse JSON file for IPv6
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

							nice, _ := json.Marshal(rule)
							tmpfile, err := ioutil.TempFile(tmpdir, "ipv6_tmp_test.json")
							if err != nil {
								log.Fatal(err)
							}
							if _, err := tmpfile.WriteString(string(nice)); err != nil {
								log.Fatal(err)
							}

							// Form expected result of parsing
							rule_want := l3Rules6{
								OutputNumber: r.gtrule,
								SrcAddr:      src6.gtAddr6.addr,
								DstAddr:      dst6.gtAddr6.addr,
								SrcMask:      src6.gtAddr6.mask,
								DstMask:      dst6.gtAddr6.mask,
								L4: l4Rules{
									IDMask:     uint8(id.gtId.idmsk),
									ID:         uint8(id.gtId.id),
									valid:      sport.gtPort.valid || dport.gtPort.valid,
									SrcPortMin: sport.gtPort.min,
									SrcPortMax: sport.gtPort.max,
									DstPortMin: dport.gtPort.min,
									DstPortMax: dport.gtPort.max,
								},
							}

							// Now we can read file, parse l2 rule and compare result with expected.
							rule_got := GetL3RulesFromJSON(tmpfile.Name())

							if !reflect.DeepEqual(rule_got.ip6[0], rule_want) {
								t.Errorf("Incorrect parse L3 ipv6 rules:\ngot: %+v \nwant: %+v\n L4 rules: \ngot: %+v \nwant: %+v\n\n",
									rule_got.ip6[0], rule_want, rule_got.ip6[0].L4, rule_want.L4)
								t.Errorf("Test JSON file %s\n\n", tmpfile.Name())
								t.FailNow()
							}

							if err := tmpfile.Close(); err != nil {
								log.Fatal(err)
							}
							os.Remove(tmpfile.Name()) // remove if test passed
						}
					}
				}
			}
		}
	}

	// If all tests passed (tmpdir is empty), remove tmpdir
	files, _ := ioutil.ReadDir(tmpdir)
	if len(files) == 0 {
		os.Remove(tmpdir)
	}
}

// Tests of ACL functions use one test packet, but many generated rules
//
// Packets used:
//
// Packet1:
// buffer := "001122334455011121314151080045000028bffd00000406eec37f0000018009090504d2162e1234567812345690501020009b540000000000000000"
// Addresses, ports, protocol types in the test packet (other fields not 0, but are not significant here)
// 	Ether:
//		SAddr = "01:11:21:31:41:51"
//		DAddr = "00:11:22:33:44:55"
//		EtherType = 0x0800
// 	IPv4:
//		SrcAddr = "127.0.0.1"
//		DstAddr = "128.9.9.5"
// 	TCP:
//		SrcPort = 1234
//		DstPort = 5678
//
// Packet2:
// buffer := "00112233445501112131415108004500001cbffd00000411eec47f0000018009090504d2162e0008dcce000000000000000000000000000000000000"
// Addresses, ports, protocol types in the test packet (other fields not 0, but are not significant here)
//	Ether:
//		SAddr = "01:11:21:31:41:51"
//		DAddr = "00:11:22:33:44:55"
//		EtherType = 0x0800
// 	IPv4:
//		SrcAddr = "127.0.0.1"
//		DstAddr = "128.9.9.5"
// 	UDP:
//		SrcPort = 1234
//		DstPort = 5678

// Tests for l4_ACL internal function on TCP packet
// This functions is called only inside l3_ACL, so we need to test it standalone first
func TestInternal_l4_ACL_packetIPv4_TCP(t *testing.T) {
	// TCP packet Packet 1
	buffer := "001122334455011121314151080045000028bffd00000406eec37f0000018009090504d2162e1234567812345690501020009b540000000000000000"
	decoded, _ := hex.DecodeString(buffer)
	pkt := new(packet.Packet)
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt.CreatePacket(mb[0])
	packet.PacketFromByte(pkt, decoded)
	pkt.ParseL4()

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

			got := l4_ACL(pkt, &rule)
			want := srcRange.ok && dstRange.ok

			if got != want {
				t.Errorf("Incorrect result for rule (%d, %d):\n got: %t\n want: %t\n Rule:%s", i, j, got, want, rule)
			}
		}
	}
}

func (rule l4Rules) String() string {
	return fmt.Sprintf("srcMin: %d, srcMax: %d, dstMin: %d, dstMax: %d, ID=%x, IDMaask=%x, valid=%t", rule.SrcPortMin, rule.SrcPortMax, rule.DstPortMin, rule.DstPortMax, rule.ID, rule.IDMask, rule.valid)
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

// Tests for l3_ACL (without call to l4_ACL)
func TestInternal_l3_ACL_packetIPv4_TCP(t *testing.T) {
	// Packet 1
	buffer := "001122334455011121314151080045000028bffd00000406eec37f0000018009090504d2162e1234567812345690501020009b540000000000000000"
	decoded, _ := hex.DecodeString(buffer)
	pkt := new(packet.Packet)
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt.CreatePacket(mb[0])
	packet.PacketFromByte(pkt, decoded)

	pkt.ParseL4()

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

				got := l3_ACL(pkt, &l3rule)
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

// Tests for l3_ACL (with call to l4_ACL) for IPv4/TCP packet
func TestInternal_l3_l4_ACL_packetIPv4_TCP(t *testing.T) {
	// Packet 1
	buffer := "001122334455011121314151080045000028bffd00000406eec37f0000018009090504d2162e1234567812345690501020009b540000000000000000"
	decoded, _ := hex.DecodeString(buffer)
	pkt := new(packet.Packet)
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt.CreatePacket(mb[0])
	packet.PacketFromByte(pkt, decoded)

	pkt.ParseL4()

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

							got := l3_ACL(pkt, &l3rule)
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

// Packet3:
// buffer := "00112233445501112131415186dd6000000000140600dead000000000000000000000000beafdead000000000000000000000000ddfd04d2162e123456781234569050102000495b0000"
// Addresses, ports, protocol types in the test packet (other fields not 0, but are not significant here)
//	Ether:
//		SAddr = "01:11:21:31:41:51"
//		DAddr = "00:11:22:33:44:55"
//		EtherType = 0x86dd
// 	IPv6:
//		SrcAddr = "dead::beaf"
//		DstAddr = "dead::ddfd"
// 	TCP:
//		SrcPort = 1234
//		DstPort = 5678

// Tests for l3_ACL (with call to l4_ACL) for IPv6/TCP packet
func TestInternal_l3_l4_ACL_packetIPv6_TCP(t *testing.T) {
	buffer := "00112233445501112131415186dd6000000000140600dead000000000000000000000000beafdead000000000000000000000000ddfd04d2162e123456781234569050102000495b0000"
	decoded, _ := hex.DecodeString(buffer)
	pkt := new(packet.Packet)
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt.CreatePacket(mb[0])
	packet.PacketFromByte(pkt, decoded)

	pkt.ParseL4()

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

							got := l3_ACL(pkt, &l3rule)
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

// Packet4:
// buffer := "00112233445501112131415186dd6000000000081100dead000000000000000000000000beafdead000000000000000000000000ddfd04d2162e00088ad5"
// Addresses, ports, protocol types in the test packet (other fields not 0, but are not significant here)
//	Ether:
//		SAddr = "01:11:21:31:41:51"
//		DAddr = "00:11:22:33:44:55"
//		EtherType = 0x86dd
// 	IPv6:
//		SrcAddr = "dead::beaf"
//		DstAddr = "dead::ddfd"
// 	UDP:
//		SrcPort = 1234
//		DstPort = 5678

// Tests for l3_ACL (with call to l4_ACL) for IPv6/UDP packet
func TestInternal_l3_l4_ACL_packetIPv6_UDP(t *testing.T) {
	buffer := "00112233445501112131415186dd6000000000081100dead000000000000000000000000beafdead000000000000000000000000ddfd04d2162e00088ad5"
	decoded, _ := hex.DecodeString(buffer)
	pkt := new(packet.Packet)
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt.CreatePacket(mb[0])
	packet.PacketFromByte(pkt, decoded)

	pkt.ParseL4()

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
		OutputNumber: []uint{1},
		//OutputNumber: []uint{0, 1, 65535},
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

							got := l3_ACL(pkt, &l3rule)
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

// Tests for l2_ACL
func TestInternal_l2_ACL(t *testing.T) {
	// Packet 1
	buffer := "001122334455011121314151080045000028bffd00000406eec37f0000018009090504d2162e1234567812345690501020009b540000000000000000"
	decoded, _ := hex.DecodeString(buffer)
	pkt := new(packet.Packet)
	mb := make([]uintptr, 1)
	low.AllocateMbufs(mb)
	pkt.CreatePacket(mb[0])
	packet.PacketFromByte(pkt, decoded)

	pkt.ParseL4()

	rulesCtxt := l2Context{
		OutputNumber: []uint{
			0,
			1,
			65535,
		},
		idMsk: []IDMask16{
			{id: 0, mask: 0, ok: true},
			{id: 0x0800, mask: 0xffff, ok: true},
			{id: 0x86dd, mask: 0xffff, ok: false},
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

					got := l2_ACL(pkt, &l2rule)
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

// Helper structs for parsing
type rawL2RulesTest struct {
	L2Rules []rawL2Rule
}

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
	gtId
}

type gtId struct {
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
