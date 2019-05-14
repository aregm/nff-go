// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"encoding/json"
	"fmt"
	"net"
)

type IPv6Address [IPv6AddrLen]uint8

func (addr IPv6Address) String() string {
	return fmt.Sprintf("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
		addr[0], addr[1], addr[2], addr[3],
		addr[4], addr[5], addr[6], addr[7],
		addr[8], addr[9], addr[10], addr[11],
		addr[12], addr[13], addr[14], addr[15])
}

// UnmarshalJSON parses IPv6 address.
func (out *IPv6Address) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}

	*out, err = StringToIPv6(str)
	return err
}

// StringToIPv6 parses IPv6 address.
func StringToIPv6(str string) (IPv6Address, error) {
	ip := net.ParseIP(str)
	if ip == nil {
		return IPv6Address{}, fmt.Errorf("Bad IPv6 address %s", str)
	}
	return NetIPToIPv6(ip)
}

// NetIPToIPv6 converts net.IP to IPv6 address.
func NetIPToIPv6(ip net.IP) (IPv6Address, error) {
	ipv6 := ip.To16()
	if ipv6 == nil {
		return IPv6Address{}, fmt.Errorf("Bad IPv6 address %v", ip)
	}
	var out IPv6Address
	copy(out[:], ipv6)
	return out, nil
}
