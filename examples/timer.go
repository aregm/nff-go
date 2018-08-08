// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var t *flow.Timer
var check *bool
var inport *uint
var duration *time.Duration

func main() {
	inport = flag.Uint("inport", 0, "port for receiver")
	duration = flag.Duration("duration", 2000*time.Millisecond, "seconds to react")
	flag.Parse()

	flow.CheckFatal(flow.SystemInit(nil))

	firstFlow, err := flow.SetReceiver(uint16(*inport))
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(firstFlow, handler, nil))
	flow.CheckFatal(flow.SetStopper(firstFlow))

	t = flow.AddTimer(*duration, react)
	flow.CheckFatal(flow.SystemStart())
}

func handler(currentPacket *packet.Packet, context flow.UserContext) {
	if check == nil {
		check = t.AddVariant(nil)
	}
	*check = true
}

func react(context flow.UserContext) {
	fmt.Println(*duration, "after last packet was arrived")

	answerPacket, _ := packet.NewPacket()
	packet.InitEmptyIPv4Packet(answerPacket, 64)
	answerPacket.SendPacket(uint16(*inport))

	check = nil
}
