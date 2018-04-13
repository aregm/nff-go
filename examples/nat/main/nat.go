// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/intel-go/nff-go/examples/nat"
	"github.com/intel-go/nff-go/flow"
)

func main() {
	// Parse arguments
	cores := flag.String("cores", "", "Specify CPU cores to use")
	configFile := flag.String("config", "config.json", "Specify config file name")
	flag.BoolVar(&nat.NoCalculateChecksum, "nocsum", false, "Specify whether to calculate checksums in modified packets")
	flag.BoolVar(&nat.NoHWTXChecksum, "nohwcsum", false, "Specify whether to use hardware offloading for checksums calculation (requires -csum)")
	dpdkLogLevel := flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()

	// Set up reaction to SIGINT (Ctrl-C)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Read config
	flow.CheckFatal(nat.ReadConfig(*configFile))

	// Init NFF-GO system at 16 available cores
	nffgoconfig := flow.Config{
		CPUList:      *cores,
		HWTXChecksum: !nat.NoHWTXChecksum,
		DPDKArgs:     []string{*dpdkLogLevel},
	}

	flow.CheckFatal(flow.SystemInit(&nffgoconfig))

	// Initialize flows and necessary state
	nat.InitFlows()

	// Start flow scheduler
	go func() {
		flow.CheckFatal(flow.SystemStart())
	}()

	// Wait for interrupt
	sig := <-c
	fmt.Printf("Received signal %v\n", sig)
	nat.CloseAllDumpFiles()
}
