// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"fmt"
	"net"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	upd "github.com/intel-go/nff-go/examples/nat/updatecfg"

	"github.com/intel-go/nff-go/common"
)

const (
	GRPCServerPort = ":60602"
)

type server struct{}

func StartGRPCServer() error {
	lis, err := net.Listen("tcp", GRPCServerPort)
	if err != nil {
		return err
	}
	s := grpc.NewServer()
	upd.RegisterUpdaterServer(s, &server{})
	// Register reflection service on gRPC server.
	reflection.Register(s)

	go func() {
		if err := s.Serve(lis); err != nil {
			common.LogWarning(common.Initialization, "Error while serving GRPC requests:", err)
		}
	}()
	return nil
}

func (s *server) ControlDump(ctx context.Context, in *upd.DumpControlRequest) (*upd.Reply, error) {
	enable := in.GetEnableTrace()
	dumpType := in.GetTraceType()
	if dumpType < upd.TraceType_DUMP_DROP || dumpType > upd.TraceType_DUMP_KNI {
		return nil, fmt.Errorf("Bad value of dump type: %d", dumpType)
	}
	DumpEnabled[dumpType] = enable

	return &upd.Reply{
		Msg: "Success",
	}, nil
}

func (s *server) ChangeInterfaceAddress(ctx context.Context, in *upd.InterfaceAddressChangeRequest) (*upd.Reply, error) {
	portId := in.GetInterfaceId()
	port, _ := Natconfig.getPortAndPairByID(portId)
	if port == nil {
		return nil, fmt.Errorf("Interface with ID %d not found", portId)
	}
	subnet, err := convertSubnet(in.GetPortSubnet())
	if err != nil {
		return nil, err
	}
	port.Subnet = *subnet

	return &upd.Reply{
		Msg: fmt.Sprintf("Successfully set port %d subnet to %s", portId, subnet.String()),
	}, nil
}

func (s *server) ChangePortForwarding(ctx context.Context, in *upd.PortForwardingChangeRequest) (*upd.Reply, error) {
	portId := in.GetInterfaceId()
	port, pp := Natconfig.getPortAndPairByID(portId)
	if port == nil {
		return nil, fmt.Errorf("Interface with ID %d not found", portId)
	}

	fp, err := convertForwardedPort(in.GetPort())
	if err != nil {
		return nil, err
	}
	err = port.checkPortForwarding(fp)
	if err != nil {
		return nil, err
	}

	pp.mutex.Lock()
	pp.deleteOldConnection(fp.Protocol.ipv6, fp.Protocol.id, int(fp.Port))
	if in.GetEnableForwarding() {
		port.enableStaticPortForward(fp)
	}
	pp.mutex.Unlock()

	return &upd.Reply{
		Msg: "Success",
	}, nil
}
