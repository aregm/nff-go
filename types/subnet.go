// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

type IPv4Subnet struct {
	Addr IPv4Address
	Mask IPv4Address
}

func (sn *IPv4Subnet) String() string {
	// Count most significant set bits
	mask := IPv4Address(1) << 31
	i := 0
	for ; i <= 32; i++ {
		if sn.Mask&mask == 0 {
			break
		}
		mask >>= 1
	}
	return sn.Addr.String() + "/" + strconv.Itoa(i)
}

// UnmarshalJSON parses ipv 4 subnet details.
func (out *IPv4Subnet) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}

	out, err = StringToIPv4Subnet(str)
	return err
}

// StringToIPv4Subnet parses IPv4 subnet.
func StringToIPv4Subnet(str string) (*IPv4Subnet, error) {
	if ip, ipnet, err := net.ParseCIDR(str); err == nil {
		return NetIPNetIPNetToIPv4Subnet(ip, ipnet)
	}

	if ip := net.ParseIP(str); ip != nil {
		var out IPv4Subnet
		var err error
		if out.Addr, err = NetIPToIPv4(ip); err != nil {
			return nil, err
		}
		out.Mask = 0xffffffff
		return &out, nil
	}
	return nil, fmt.Errorf("Failed to parse address ", str)
}

func NetIPNetIPNetToIPv4Subnet(ip net.IP, ipnet *net.IPNet) (*IPv4Subnet, error) {
	var out IPv4Subnet
	var err error
	if out.Addr, err = NetIPToIPv4(ip); err != nil {
		return nil, err
	}
	if len(ipnet.Mask) > 4 {
		return nil, fmt.Errorf("Bad IP mask: %v", ipnet)
	}
	out.Mask = BytesToIPv4(ipnet.Mask[0], ipnet.Mask[1], ipnet.Mask[2], ipnet.Mask[3])
	return &out, nil
}

func NetIPNetToIPv4Subnet(ipnet *net.IPNet) (*IPv4Subnet, error) {
	var out IPv4Subnet
	var err error
	if out.Addr, err = NetIPToIPv4(ipnet.IP); err != nil {
		return nil, err
	}
	if len(ipnet.Mask) > 4 {
		return nil, fmt.Errorf("Bad IP mask: %v", ipnet)
	}
	out.Mask = BytesToIPv4(ipnet.Mask[0], ipnet.Mask[1], ipnet.Mask[2], ipnet.Mask[3])
	return &out, nil
}

// CheckIPv4AddressWithinSubnet returns true if IPv4 addr is inside of specified subnet.
func (sn *IPv4Subnet) CheckIPv4AddressWithinSubnet(addr IPv4Address) bool {
	return addr&sn.Mask == sn.Addr&sn.Mask
}

type IPv6Subnet struct {
	Addr IPv6Address
	Mask IPv6Address
}

func (sn *IPv6Subnet) String() string {
	// Count most significant set bits
	i := 0
	for ; i <= 128; i++ {
		mask := uint8(1) << uint(7-(i&7))
		if i == 128 || sn.Mask[i>>3]&mask == 0 {
			break
		}
	}
	return sn.Addr.String() + "/" + strconv.Itoa(i)
}

// UnmarshalJSON parses ipv 6 subnet details.
func (out *IPv6Subnet) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	if ip, ipnet, err := net.ParseCIDR(s); err == nil {
		if ip.To16() == nil {
			return fmt.Errorf("Bad IPv6 address: %s", s)
		}
		copy(out.Addr[:], ip.To16())
		copy(out.Mask[:], ipnet.Mask)
		return nil
	}

	if ip := net.ParseIP(s); ip != nil {
		if ip.To16() == nil {
			return fmt.Errorf("Bad IPv6 address: %s", s)
		}
		copy(out.Addr[:], ip.To16())
		out.Mask = IPv6Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		return nil
	}
	return fmt.Errorf("Failed to parse address ", s)
}

// AndIPv6Mask performs bit AND operation for IPv6 address and mask.
func (sn *IPv6Subnet) AndIPv6Mask(addr IPv6Address) IPv6Address {
	var result IPv6Address
	for i := range addr {
		result[i] = addr[i] & sn.Mask[i]
	}
	return result
}

// CheckIPv6AddressWithinSubnet returns true if IPv6 addr is inside of specified subnet.
func (sn *IPv6Subnet) CheckIPv6AddressWithinSubnet(addr IPv6Address) bool {
	return sn.AndIPv6Mask(addr) == sn.AndIPv6Mask(sn.Addr)
}
