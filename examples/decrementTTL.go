// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

// Main function for constructing packet processing graph.
func main() {
	inPort := flag.Uint("inPort", 0, "port for receiver")
	outPort := flag.Uint("outPort", 1, "port for sender")
	flag.Parse()

	flow.SystemInit(nil)
	inputFlow, _ := flow.SetReceiver(uint16(*inPort))
	flow.SetHandlerDrop(inputFlow, decrementTTL, nil)
	flow.SetSender(inputFlow, uint16(*outPort))
	flow.SystemStart()
}

func decrementTTL(current *packet.Packet, c flow.UserContext) bool {
	current.ParseL3() // must parse before header can be read
	header := current.GetIPv4()
	if header == nil { // not IPv4
		return false
	}

	header.TimeToLive--
	if header.TimeToLive == 0 { // TTL exceeded, drop
		return false
	} else {
		return true
	}
}
