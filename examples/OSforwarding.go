// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/nff-go/flow"
)

func main() {
	inport := flag.String("in", "", "device for receiver")
	outport := flag.String("out", "", "device for sender")
	flag.Parse()

	flow.CheckFatal(flow.SystemInit(nil))

	inputFlow, err := flow.SetReceiverOS(*inport)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetSenderOS(inputFlow, *outport))

	flow.CheckFatal(flow.SystemStart())
}
