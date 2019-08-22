// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/nff-go/flow"
)

func main() {
	// If you use af-xdp mode you need to configure queues:
	// e.g. ethtool -N my_device flow-type tcp4 dst-port 4242 action 16
	afXDP := flag.Bool("af-xdp", false, "use af-xdp. need to use ethtool to setup queues")
	inport := flag.String("in", "", "device for receiver")
	inQueue := flag.Int("in-queue", 16, "queue for receiver")
	outport := flag.String("out", "", "device for sender")
	flag.Parse()

	flow.CheckFatal(flow.SystemInit(nil))
	if *afXDP {
		inputFlow, err := flow.SetReceiverXDP(*inport, *inQueue)
		flow.CheckFatal(err)
		flow.CheckFatal(flow.SetSenderXDP(inputFlow, *outport))
	} else {
		inputFlow, err := flow.SetReceiverOS(*inport)
		flow.CheckFatal(err)
		flow.CheckFatal(flow.SetSenderOS(inputFlow, *outport))
	}
	flow.CheckFatal(flow.SystemStart())
}
