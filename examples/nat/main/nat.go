// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/intel-go/nff-go/examples/nat"
	upd "github.com/intel-go/nff-go/examples/nat/updatecfg"
	"github.com/intel-go/nff-go/flow"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	port = ":60602"
)

type server struct{}

// UpdateNATConfigPublicSubnet implements updatecfg.Updater
func (s *server) UpdateNATConfigPublicSubnet(ctx context.Context, in *upd.UpdatePublicRequest) (*upd.UpdateReply, error) {
	privPort := in.Upd.GetPrivatePort()
	publPort := in.Upd.GetPublicPort()

	for id, pp := range nat.Natconfig.PortPairs {
		if pp.PrivatePort.Index == uint16(privPort) && pp.PublicPort.Index == uint16(publPort) {
			fmt.Println("Updating public subnet for port pair", id)
			pubIp, pubIpnet, err := net.ParseCIDR(in.Upd.GetPublicSubnet())
			if err != nil {
				return &upd.UpdateReply{Message: "Cannot parse public IP"}, err
			}

			nat.Natconfig.PortPairs[id].PublicPort.Subnet.Addr, err = nat.ConvertIPv4(pubIp.To4())
			nat.Natconfig.PortPairs[id].PublicPort.Subnet.Mask, err = nat.ConvertIPv4(pubIpnet.Mask)
			if err != nil {
				return &upd.UpdateReply{Message: "Cannot ConvertIPv4 public IP"}, err
			}
			return &upd.UpdateReply{Message: "Table entry updated: new publ subnet=" + in.Upd.GetPublicSubnet()}, nil
		}
	}
	return &upd.UpdateReply{Message: "No entry to update found for privPort=" + fmt.Sprint(in.Upd.GetPrivatePort()) + ", publPort=" + fmt.Sprint(in.Upd.GetPublicPort())}, nil
}

// UpdateNATConfigPrivateSubnet implements updatecfg.Updater
// Updates also port forwarding addresses
func (s *server) UpdateNATConfigPrivateSubnet(ctx context.Context, in *upd.UpdatePrivateRequest) (*upd.UpdateReply, error) {
	privPort := in.Upd.GetPrivatePort()
	publPort := in.Upd.GetPublicPort()
	fwdPortDst := in.Upd.GetPortFwdDst()

	for id, pp := range nat.Natconfig.PortPairs {
		if pp.PrivatePort.Index == uint16(privPort) && pp.PublicPort.Index == uint16(publPort) {
			fmt.Println("Updating private subnet for port pair", id)
			privIp, privIpnet, err := net.ParseCIDR(in.Upd.GetPrivateSubnet())
			if err != nil {
				return &upd.UpdateReply{Message: "Cannot parse private IP"}, err
			}
			nat.Natconfig.PortPairs[id].PrivatePort.Subnet.Addr, err = nat.ConvertIPv4(privIp.To4())
			nat.Natconfig.PortPairs[id].PrivatePort.Subnet.Mask, err = nat.ConvertIPv4(privIpnet.Mask)
			if err != nil {
				return &upd.UpdateReply{Message: "Cannot ConvertIPv4 private IP"}, err
			}

			fwdIp, _, err := net.ParseCIDR(fwdPortDst)
			forwardedPorts := nat.Natconfig.PortPairs[id].PublicPort.ForwardPorts
			fmt.Printf("Forwarded ports before: %+v\n\n", forwardedPorts)
			for i := 0; i < len(forwardedPorts); i++ {
				forwardedPorts[i].Destination.Addr, err = nat.ConvertIPv4(fwdIp.To4())
				if err != nil {
					return &upd.UpdateReply{Message: "Cannot convert PortFwdDst IP"}, err
				}
			}
			fmt.Printf("Forwarded ports after: %+v\n\n", forwardedPorts)
			return &upd.UpdateReply{Message: "Table entry updated: new priv subnet=" + in.Upd.GetPrivateSubnet()}, nil
		}
	}
	return &upd.UpdateReply{Message: "No entry to update found for privPort=" + fmt.Sprint(in.Upd.GetPrivatePort()) + ", publPort=" + fmt.Sprint(in.Upd.GetPublicPort())}, nil
}

func main() {
	// Parse arguments
	cores := flag.String("cores", "", "Specify CPU cores to use")
	configFile := flag.String("config", "config.json", "Specify config file name")
	flag.BoolVar(&nat.NoCalculateChecksum, "nocsum", false, "Specify whether to calculate checksums in modified packets")
	flag.BoolVar(&nat.NoHWTXChecksum, "nohwcsum", false, "Specify whether to use hardware offloading for checksums calculation (requires -csum)")
	noscheduler := flag.Bool("no-scheduler", false, "disable scheduler")
	dpdkLogLevel := flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	flag.Parse()

	// Set up reaction to SIGINT (Ctrl-C)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Read config
	flow.CheckFatal(nat.ReadConfig(*configFile))

	// Init NFF-GO system at 16 available cores
	nffgoconfig := flow.Config{
		CPUList:          *cores,
		HWTXChecksum:     !nat.NoHWTXChecksum,
		DPDKArgs:         []string{*dpdkLogLevel},
		DisableScheduler: *noscheduler,
		NeedKNI:          nat.NeedKNI,
	}

	flow.CheckFatal(flow.SystemInit(&nffgoconfig))

	offloadingAvailable := nat.CheckHWOffloading()
	if !nat.NoHWTXChecksum && !offloadingAvailable {
		println("Warning! Requested hardware offloading is not available on all ports. Falling back to software checksum calculation.")
		nat.NoHWTXChecksum = true
		flow.SetUseHWCapability(flow.HWTXChecksumCapability, false)
	}

	// Initialize flows and necessary state
	nat.InitFlows()

	go func() {
		lis, err := net.Listen("tcp", port)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		s := grpc.NewServer()
		upd.RegisterUpdaterServer(s, &server{})
		// Register reflection service on gRPC server.
		reflection.Register(s)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// Start flow scheduler
	go func() {
		flow.CheckFatal(flow.SystemStart())
	}()

	// Wait for interrupt
	sig := <-c
	fmt.Printf("Received signal %v\n", sig)
	nat.CloseAllDumpFiles()
}
