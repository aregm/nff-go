// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	"github.com/intel-go/nff-go/flow"

	"github.com/intel-go/nff-go/examples/lb"
)

func main() {
	cores := flag.String("cores", "", "Specify CPU cores to use.")
	configFile := flag.String("config", "config.json", "Specify config file name.")
	noscheduler := flag.Bool("no-scheduler", false, "Disable scheduler.")
	dpdkLogLevel := flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL.")
	flag.Parse()

	// Read config
	flow.CheckFatal(lb.ReadConfig(*configFile))

	nffgoconfig := flow.Config{
		CPUList:          *cores,
		DPDKArgs:         []string{*dpdkLogLevel},
		DisableScheduler: *noscheduler,
	}

	flow.CheckFatal(flow.SystemInit(&nffgoconfig))
	lb.InitFlows()
	flow.CheckFatal(flow.SystemStart())
}
