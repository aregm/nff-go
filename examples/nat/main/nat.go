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
	yanffconfig := flow.Config {
		CPUCoresNumber: *cores,
	}

	flow.SystemInit(&yanffconfig)

	// Get port MACs
	nat.PublicMAC = flow.GetPortMACAddress(nat.Natconfig.PublicPort.Index)
	nat.PrivateMAC = flow.GetPortMACAddress(nat.Natconfig.PrivatePort.Index)

	// Initialize public to private flow
	publicToPrivate := flow.SetReceiver(nat.Natconfig.PublicPort.Index)
	flow.SetHandler(publicToPrivate, nat.PublicToPrivateTranslation, nil)
	flow.SetSender(publicToPrivate, nat.Natconfig.PrivatePort.Index)

	// Initialize private to public flow
	privateToPublic := flow.SetReceiver(nat.Natconfig.PrivatePort.Index)
	flow.SetHandler(privateToPublic, nat.PrivateToPublicTranslation, nil)
	flow.SetSender(privateToPublic, nat.Natconfig.PublicPort.Index)

	flow.SystemStart()
}
