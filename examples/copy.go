// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "github.com/intel-go/yanff/flow"

func main() {
	config := flow.Config{}

	// Initialize YANFF library at 15 cores by default
	flow.SystemInit(&config)

	a := flow.SetReceiver(uint8(0))
	b := flow.SetCopier(a)
	flow.SetSender(a, uint8(1))
	flow.SetSender(b, uint8(2))

	flow.SystemStart()
}
