// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"github.com/intel-go/nff-go/examples/nffPktgen/generator"
	"github.com/intel-go/nff-go/flow"
)

func main() {
	var (
		speed            uint64
		genConfig, cores string
		port             uint
	)
	flag.Uint64Var(&speed, "speed", 120000000, "speed of fast generator, Pkts/s")
	flag.StringVar(&genConfig, "config", "ip4.json", "specifies config for generator")
	flag.StringVar(&cores, "cores", "0-2", "specifies cores")
	flag.UintVar(&port, "port", 1, "specifies output port")
	flag.Parse()

	// Init NFF-GO system at 16 available cores
	config := flow.Config{
		CPUList: cores,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	configuration, err := generator.ReadConfig(genConfig)
	if err != nil {
		panic(fmt.Sprintf("%s config reading failed: %v", genConfig, err))
	}
	context, err := generator.GetContext(configuration)
	flow.CheckFatal(err)
	outFlow, _, _ := flow.SetFastGenerator(generator.Generate, speed, context)
	flow.CheckFatal(flow.SetSender(outFlow, uint16(port)))
	flow.CheckFatal(flow.SystemStart())
}
