// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lb

import (
	"fmt"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

func arpHandler(pkt *packet.Packet, ctx flow.UserContext) bool {
	pkt.ParseL3()
	protocol := pkt.Ether.EtherType

	if protocol == types.SwapARPNumber {
		err := LBConfig.TunnelPort.neighCache.HandleIPv4ARPPacket(pkt)
		if err != nil {
			fmt.Println(err)
		}
		return false
	}
	return true
}
