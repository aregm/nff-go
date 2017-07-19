// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"encoding/json"
	"github.com/intel-go/yanff/common"
	"os"
)

type IPSubnet struct {
	Sigbits int `json:"bits"`
}

type IPv4Subnet struct {
	Address uint32 `json:"address"`
	IPSubnet
}

type IPv6Subnet struct {
	Address [common.IPv6AddrLen]uint8 `json:"address"`
	IPSubnet
}

type IPv4Port struct {
	Index         uint8
	DstMACAddress [common.EtherAddrLen]uint8 `json:"gateway-mac"`
	IPv4Subnet
}

type Config struct {
	PrivatePort   IPv4Port `json:"private-ports"`
	PublicPort    IPv4Port `json:"public-port"`
}

// readConfig function reads and parses config file
func ReadConfig(fileName string) (*Config, error) {
	var config Config

	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(file)

	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
