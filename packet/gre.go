// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"fmt"

	"github.com/intel-go/nff-go/types"
)

type GREHdr struct {
	Flags     uint16
	NextProto uint16
}

func (hdr *GREHdr) String() string {
	return fmt.Sprintf("GRE: flags = 0x%04x, embedded protocol = 0x%04x",
		hdr.Flags, hdr.NextProto)
}

// GetGREForIPv4 casts L4 pointer to *GREHdr type.
func (packet *Packet) GetGREForIPv4() *GREHdr {
	if packet.GetIPv4NoCheck().NextProtoID == types.GRENumber {
		return (*GREHdr)(packet.L4)
	}
	return nil
}

// GetGRENoCheck casts L4 pointer to *GREHdr type.
func (packet *Packet) GetGRENoCheck() *GREHdr {
	return (*GREHdr)(packet.L4)
}
