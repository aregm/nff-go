// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"

	"github.com/intel-go/yanff/flow"
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	config := flow.Config{}

	// Initialize YANFF library at 15 cores by default
	CheckFatal(flow.SystemInit(&config))

	a, err := flow.SetReceiver(uint8(0))
	CheckFatal(err)

	b, err := flow.SetCopier(a)
	CheckFatal(err)

	CheckFatal(flow.SetSender(a, uint8(1)))
	CheckFatal(flow.SetSender(b, uint8(2)))

	CheckFatal(flow.SystemStart())
}
