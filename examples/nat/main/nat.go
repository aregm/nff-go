// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"github.com/intel-go/yanff/examples/nat"
	"github.com/intel-go/yanff/flow"
	"log"
	"os"
)

func main() {
	// Read config
	configFile := "config.json"

	if len(os.Args) > 1 {
		index := 1

		if len(os.Args) > index {
			configFile = os.Args[index]
		}
	}

	var err error
	nat.Natconfig, err = nat.ReadConfig(configFile)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("NAT config:", nat.Natconfig)

	cores := flag.Uint("cores", 16, "Specify number of CPU cores to use")
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
