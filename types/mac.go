// Copyright 2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"encoding/json"
	"fmt"
	"net"
)

type MACAddress [EtherAddrLen]uint8

// MACToString return MAC address like string
func (mac MACAddress) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// StringToMACAddress parses a string which contains a MAC address.
func StringToMACAddress(str string) (MACAddress, error) {
	hw, err := net.ParseMAC(str)
	if err != nil {
		return MACAddress{}, err
	}
	var out MACAddress
	copy(out[:], hw)
	return out, nil
}

// UnmarshalJSON parses JSON element which contains string which
// contains MAC address.
func (out *MACAddress) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*out, err = StringToMACAddress(s)
	return err
}
