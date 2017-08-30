// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"encoding/json"
	"errors"
	"github.com/intel-go/yanff/common"
	"net"
	"os"
)

type IPv4Subnet struct {
	Addr    uint32
	Mask    uint32
}

type MACAddress [common.EtherAddrLen]uint8

type IPv4Port struct {
	Index         uint8      `json:"index"`
	DstMACAddress MACAddress `json:"dst_mac"`
	Subnet        IPv4Subnet `json:"subnet"`
}

type Config struct {
	PrivatePort   IPv4Port   `json:"private-port"`
	PublicPort    IPv4Port   `json:"public-port"`
}

func convertIPv4(in []byte) (uint32, error) {
	if in == nil || len(in) > 4 {
		return 0, errors.New("Only IPv4 addresses are supported now")
	}

	addr := (uint32(in[0]) << 24) | (uint32(in[1]) << 16) |
		(uint32(in[2]) << 8) | uint32(in[3])

	return addr, nil
}

func (out *IPv4Subnet) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	if ip, ipnet, err := net.ParseCIDR(s); err == nil {
		if out.Addr, err = convertIPv4(ip.To4()); err != nil {
			return err
		}
		if out.Mask, err = convertIPv4(ipnet.Mask); err != nil {
			return err
		}
		return nil
	}

	if ip := net.ParseIP(s); ip != nil {
		var err error
		if out.Addr, err = convertIPv4(ip.To4()); err != nil {
			return err
		}
		out.Mask = 0xffffffff
		return nil
	} else {
		return errors.New("Failed to parse address " + s)
	}
}

func (out *MACAddress) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	if hw, err := net.ParseMAC(s); err == nil {
		copy(out[:], hw)
		return nil
	} else {
		return err
	}
}

// readConfig function reads and parses config file
func ReadConfig(fileName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(file)

	err = decoder.Decode(&Natconfig)
	if err != nil {
		return err
	}

	if debug {
		println("NAT config:", Natconfig)
	}
	return nil
}
