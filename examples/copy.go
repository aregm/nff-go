// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/intel-go/nff-go/flow"
)

func main() {
	flow.CheckFatal(flow.SystemInit(nil))

	a, err := flow.SetReceiver(0)
	flow.CheckFatal(err)

	b, err := flow.SetCopier(a)
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetSender(a, 1))
	flow.CheckFatal(flow.SetSender(b, 2))

	flow.CheckFatal(flow.SystemStart())
}
