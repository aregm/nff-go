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

// UpdateNATConfig implements updatecfg.Updater
func (s *server) UpdateNATConfig(ctx context.Context, in *upd.UpdateRequest) (*upd.UpdateReply, error) {
	privIp, privIpnet, err := net.ParseCIDR(in.Upd.GetPrivateSubnet())
	if err != nil {
		return &upd.UpdateReply{Message: "Cannot parse private IP"}, err
	}
	nat.Natconfig.PortPairs[0].PrivatePort.Subnet.Addr, err = nat.ConvertIPv4(privIp.To4())
	nat.Natconfig.PortPairs[0].PublicPort.Subnet.Mask, err = nat.ConvertIPv4(privIpnet.Mask)
	if err != nil {
		return &upd.UpdateReply{Message: "Cannot ConvertIPv4 private IP"}, err
	}

	pubIp, pubIpnet, err := net.ParseCIDR(in.Upd.GetPublicSubnet())
	if err != nil {
		return &upd.UpdateReply{Message: "Cannot parse public IP"}, err
	}
	nat.Natconfig.PortPairs[0].PublicPort.Subnet.Addr, err = nat.ConvertIPv4(pubIp.To4())
	nat.Natconfig.PortPairs[0].PublicPort.Subnet.Mask, err = nat.ConvertIPv4(pubIpnet.Mask)
	if err != nil {
		return &upd.UpdateReply{Message: "Cannot ConvertIPv4 public IP"}, err
	}

	hw, err := net.ParseMAC(in.Upd.GetPublicDstMac())
	if err != nil {
		return &upd.UpdateReply{Message: "Cannot parse dst MAC"}, err
	}
	copy(nat.Natconfig.PortPairs[0].PublicPort.DstMACAddress[:], hw)

	return &upd.UpdateReply{Message: "Table updated: priv=" + in.Upd.GetPrivateSubnet() + ", publ=" + in.Upd.GetPublicSubnet() + ", public_dst_mac=" + in.Upd.GetPublicDstMac()}, nil
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
