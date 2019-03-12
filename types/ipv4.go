// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"encoding/json"
	"fmt"
	"net"

	"strconv"
	"strings"
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

// parse ip address string to int ip
func StringToIPv4(ipaddr string) IPv4Address {
	str_ary := strings.Split(ipaddr, ".")
	bIp := [4]byte{}

	i := 0
	for _, element := range str_ary {
		val, err := strconv.Atoi(element)
		if err != nil {
			panic(err)
		}
		bIp[i] = byte(val)
		i++
	}
	return ArrayToIPv4(bIp)
}
