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
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	if ip := net.ParseIP(s); ip != nil {
		ipv4 := ip.To4()
		if ipv4 == nil {
			return fmt.Errorf("Bad IPv4 address %s", s)
		}
		*out = BytesToIPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		return nil
	}
	return fmt.Errorf("Failed to parse address %s", s)
}

// NextIP returns the next ip address specified by the inc.
func NextIP(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

// IncrementIP increments all bytes in IPv4 address.
func IncrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Ip2int convert IPv4 address to int
func Ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

// Int2ip converts int ip to net.IP.
func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
