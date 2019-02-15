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
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	if ip := net.ParseIP(s); ip != nil {
		ipv6 := ip.To16()
		if ipv6 == nil {
			return fmt.Errorf("Bad IPv6 address %s", s)
		}
		copy((*out)[:], ipv6)
		return nil
	}
	return fmt.Errorf("Failed to parse address %s", s)
}
