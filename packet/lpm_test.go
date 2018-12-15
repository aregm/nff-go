// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/intel-go/nff-go/common"
)

func init() {
	tInitDPDK()
	rand.Seed(time.Now().UTC().UnixNano())
}

var zero common.IPv4Address = 0
var next common.IPv4Address

var stepM = 1000
var stepN = 10
var stepK = 250

func TestOneRule(t *testing.T) {
	lpm := CreateLPM("lpm", 0, 100, 256*256)
	for i := 0; i < stepM; i++ {
		ip_number := 1 + rand.Intn(32)
		mask_len := uint8(1 + rand.Intn(32))
		next_hop := common.IPv4Address(rand.Intn(100))
		// Construct ip
		ip := constructIP(ip_number)

		// Construct mask
		mask := zero
		for u := zero; u < common.IPv4Address(mask_len); u++ {
			mask = mask | (1 << (31 - u))
		}

		// Add rule
		lpm.Add(ip, mask_len, next_hop)

		// Check
		for j := 0; j < stepN; j++ {
			trueN, falseN, trueIP, falseIP := testIP(ip, mask_len)

			for k := 0; k < trueN; k++ {
				answer := lpm.Lookup(trueIP[k], &next)
				if answer == false {
					t.Errorf("Didn't find right IP: rule_ip: %d, depth: %d, checking_ip: %d", ip, mask_len, trueIP[k])
				} else if next != 0x00FFFFFF&(next_hop) {
					t.Errorf("Wrong next hop: rule_ip: %d, depth: %d, checking_ip: %d, rule_next_hop: %d, returned_next_hop: %d", ip, mask_len, trueIP[k], next_hop, next)
				}
			}
			for k := 0; k < falseN; k++ {
				answer := lpm.Lookup(falseIP[k], &next)
				if answer == true {
					t.Errorf("Found wrong IP:: rule_ip: %d, depth: %d, checking_ip: %d", ip, mask_len, falseIP[k])
				}
			}
			next = 0
		}

		// Delete rule
		lpm.Delete(ip, mask_len)
	}
	lpm.Free()
}

func TestMultipleRules(t *testing.T) {
	lpm := CreateLPM("lpm", 0, 100, 256*256)
	lpm.Add(0x10000000, 8, 1)
	lpm.Add(0x10100000, 14, 2)
	lpm.Add(0x10101000, 25, 3)
	lpm.Add(0x20001011, 32, 29)
	lpm.Add(0x10101011, 32, 5)
	lpm.Add(0x10101010, 30, 4)
	lpm.Add(0x10100000, 14, 9)
	answer := lpm.Lookup(0x10101010, &next)
	if answer != true && next != 4 {
		t.Errorf("Multiple rules, 1 checking fails")
	}
	answer = lpm.Lookup(0x10101011, &next)
	if answer != true && next != 5 {
		t.Errorf("Multiple rules, 2 checking fails")
	}
	answer = lpm.Lookup(0x10101020, &next)
	if answer != true && next != 3 {
		t.Errorf("Multiple rules, 3 checking fails")
	}
	answer = lpm.Lookup(0x20101011, &next)
	if answer != false {
		t.Errorf("Multiple rules, 4 checking fails")
	}
	answer = lpm.Lookup(0x10201011, &next)
	if answer != true && next != 1 {
		t.Errorf("Multiple rules, 5 checking fails")
	}
	answer = lpm.Lookup(0x20001011, &next)
	if answer != true && next != 29 {
		t.Errorf("Multiple rules, 6 checking fails")
	}

	lpm.Add(0x10101000, 25, 33)
	answer = lpm.Lookup(0x10101020, &next)
	if answer != true && next != 33 {
		t.Errorf("Multiple rules, 7 checking fails")
	}

	if lpm.Delete(0x55555555, 8) == 0 {
		t.Errorf("Removal of non-existing rule 1 fails")
	}

	lpm.Delete(0x10101011, 32)
	answer = lpm.Lookup(0x10101011, &next)
	if answer != true && next != 4 {
		t.Errorf("Multiple rules, 8 checking fails")
	}

	if lpm.Delete(0x10101011, 32) == 0 {
		t.Errorf("Removal of non-existing rule 2 fails")
	}

	lpm.Delete(0x10000000, 8)
	lpm.Delete(0x10100000, 14)
	lpm.Delete(0x10101000, 25)
	lpm.Delete(0x20001011, 32)
	lpm.Delete(0x10101010, 30)
	lpm.Delete(0x10100000, 14)

	lpm.Free()
}

func constructIP(ip_number int) common.IPv4Address {
	var ip common.IPv4Address
	if ip_number < 16 {
		ip = zero
		for j := 0; j < ip_number; j++ {
			one := zero
			for ip|one == ip {
				one = 1 << uint(rand.Intn(32))
			}
			ip = ip | one
		}
	} else {
		ip = ^zero
		for j := 0; j < 32-ip_number; j++ {
			one := ^zero
			for ip&one == ip {
				one = ^(1 << uint(rand.Intn(32)))
			}
			ip = ip & one
		}
	}
	return ip
}

func testIP(ip common.IPv4Address, mask_len uint8) (int, int, []common.IPv4Address, []common.IPv4Address) {
	right := int(math.Pow(2, float64(32-mask_len)))
	wrong := int(math.Pow(2, float64(mask_len)) - 1)

	rightN := rand.Intn(right)%stepK + 1
	wrongN := rand.Intn(wrong)%stepK + 1

	rightIP := make([]common.IPv4Address, rightN, rightN)
	wrongIP := make([]common.IPv4Address, wrongN, wrongN)

	rightIP[0] = ip
	for i := 1; i < rightN; i++ {
		rightIP[i] = ip
		for j := uint8(0); j < 31-mask_len; j++ {
			if rand.Intn(2) == 1 {
				rightIP[i] = rightIP[i] ^ (1 << j)
			}
		}
	}
	wrongIP[0] = ^ip
	p := 31 - uint8(rand.Intn(int(mask_len)))
	for i := 1; i < wrongN; i++ {
		wrongIP[i] = ip
		for j := 32 - mask_len; j < 32; j++ {
			if rand.Intn(2) == 1 || j == p {
				wrongIP[i] = wrongIP[i] ^ (1 << j)
			}
		}
	}
	return rightN, wrongN, rightIP, wrongIP
}
