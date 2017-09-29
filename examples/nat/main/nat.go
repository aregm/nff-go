// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/yanff/examples/nat"
	"github.com/intel-go/yanff/flow"
	"log"
)

func main() {
	// Parse arguments
	cores := flag.Uint("cores", 44, "Specify number of CPU cores to use")
	configFile := flag.String("config", "config.json", "Specify config file name")
	flag.Parse()

	// Read config
	err := nat.ReadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	// Init YANFF system at 16 available cores
	yanffconfig := flow.Config{
		CPUCoresNumber: *cores,
	}

	flow.SystemInit(&yanffconfig)

	// Read MAC addresses for local ports
	nat.InitLocalMACs()
	nat.InitFlows()

	flow.SystemStart()
}
