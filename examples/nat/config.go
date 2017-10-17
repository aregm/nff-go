// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"encoding/json"
	"errors"
	"net"
	"os"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/flow"
)

type ipv4Subnet struct {
	Addr uint32
	Mask uint32
}

type macAddress [common.EtherAddrLen]uint8

type ipv4Port struct {
	Index         uint8      `json:"index"`
	DstMACAddress macAddress `json:"dst_mac"`
	Subnet        ipv4Subnet `json:"subnet"`
}

// Config for one port pair.
type portPairsConfig struct {
	PrivatePort ipv4Port `json:"private-port"`
	PublicPort  ipv4Port `json:"public-port"`
}

// Config for NAT.
type Config struct {
	PortPairs []portPairsConfig `json:"port-pairs"`
}

type pairIndex struct {
	index int
}

var (
	// PublicMAC is a public port MAC address.
	PublicMAC [][common.EtherAddrLen]uint8
	// PrivateMAC is a private port MAC address.
	PrivateMAC [][common.EtherAddrLen]uint8
	// Natconfig is a config file.
	Natconfig *Config
	// Flag whether checksums should be calculated for modified packets.
	CalculateChecksum bool
	// Flag whether checksums calculation should be offloaded to HW.
	HWTXChecksum bool
)

func (pi pairIndex) Copy() interface{} {
	return pairIndex{
		index: pi.index,
	}
}

func (pi pairIndex) Delete() {
}

func convertIPv4(in []byte) (uint32, error) {
	if in == nil || len(in) > 4 {
		return 0, errors.New("Only IPv4 addresses are supported now")
	}

	addr := (uint32(in[0]) << 24) | (uint32(in[1]) << 16) |
		(uint32(in[2]) << 8) | uint32(in[3])

	return addr, nil
}

// UnmarshalJSON parses ipv 4 subnet details.
func (out *ipv4Subnet) UnmarshalJSON(b []byte) error {
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
	}
	return errors.New("Failed to parse address " + s)
}

// UnmarshalJSON parses MAC address.
func (out *macAddress) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	hw, err := net.ParseMAC(s)
	if err != nil {
		return err
	}

	copy(out[:], hw)
	return nil
}

// ReadConfig function reads and parses config file
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

	return nil
}

func InitLocalMACs() {
	PublicMAC = make([][common.EtherAddrLen]uint8, len(Natconfig.PortPairs))
	PrivateMAC = make([][common.EtherAddrLen]uint8, len(Natconfig.PortPairs))
	// Get port MACs
	for i := range Natconfig.PortPairs {
		PublicMAC[i] = flow.GetPortMACAddress(Natconfig.PortPairs[i].PublicPort.Index)
		PrivateMAC[i] = flow.GetPortMACAddress(Natconfig.PortPairs[i].PrivatePort.Index)
	}
}

func InitFlows() {
	for i := range Natconfig.PortPairs {
		// Handler context with handler index
		context := new(pairIndex)
		context.index = i

		// Initialize public to private flow
		publicToPrivate := flow.SetReceiver(Natconfig.PortPairs[i].PublicPort.Index)
		flow.SetHandler(publicToPrivate, PublicToPrivateTranslation, context)
		flow.SetSender(publicToPrivate, Natconfig.PortPairs[i].PrivatePort.Index)

		// Initialize private to public flow
		privateToPublic := flow.SetReceiver(Natconfig.PortPairs[i].PrivatePort.Index)
		flow.SetHandler(privateToPublic, PrivateToPublicTranslation, context)
		flow.SetSender(privateToPublic, Natconfig.PortPairs[i].PublicPort.Index)
	}
}
