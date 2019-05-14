// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"encoding/json"
	"fmt"
	"net"
)

type IPv4Address uint32

// BytesToIPv4 converts four element address to IPv4Address representation
func BytesToIPv4(a byte, b byte, c byte, d byte) IPv4Address {
	return IPv4Address(d)<<24 | IPv4Address(c)<<16 | IPv4Address(b)<<8 | IPv4Address(a)
}

// ArrayToIPv4 converts four element array to IPv4Address representation
func ArrayToIPv4(a [IPv4AddrLen]byte) IPv4Address {
	return IPv4Address(a[3])<<24 | IPv4Address(a[2])<<16 | IPv4Address(a[1])<<8 | IPv4Address(a[0])
}

// SliceToIPv4 converts four element slice to IPv4Address representation
func SliceToIPv4(s []byte) IPv4Address {
	return IPv4Address(s[3])<<24 | IPv4Address(s[2])<<16 | IPv4Address(s[1])<<8 | IPv4Address(s[0])
}

// IPv4ToBytes converts four element address to IPv4Address representation
func IPv4ToBytes(v IPv4Address) [IPv4AddrLen]byte {
	return [IPv4AddrLen]uint8{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func (addr IPv4Address) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
}

func IPv4ArrayToString(addr [IPv4AddrLen]uint8) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
}

// UnmarshalJSON parses IPv4 address.
func (out *IPv4Address) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}

	*out, err = StringToIPv4(str)
	return err
}

// StringToIPv4 parses IPv4 address.
func StringToIPv4(str string) (IPv4Address, error) {
	ip := net.ParseIP(str)
	if ip == nil {
		return IPv4Address(0), fmt.Errorf("Bad IPv4 address %s", str)
	}
	return NetIPToIPv4(ip)
}

// NetIPToIPv4 converts net.IP to IPv4 address.
func NetIPToIPv4(ip net.IP) (IPv4Address, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return IPv4Address(0), fmt.Errorf("Bad IPv4 address %v", ip)
	}
	return BytesToIPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3]), nil
}

// IPv4ToNetIP converts IPv4 to net.IP address.
func IPv4ToNetIP(ip IPv4Address) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}
