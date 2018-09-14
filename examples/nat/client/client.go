package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	upd "github.com/intel-go/nff-go/examples/nat/updatecfg"
)

type dumpRequestArray []*upd.DumpControlRequest
type addresChangeRequestArray []*upd.InterfaceAddressChangeRequest
type portForwardRequestArray []*upd.PortForwardingChangeRequest

var (
	dumpRequests         dumpRequestArray
	addresChangeRequests addresChangeRequestArray
	portForwardRequests  portForwardRequestArray
)

func (dra *dumpRequestArray) String() string {
	res := ""
	for _, r := range *dra {
		res += r.String() + "\n"
	}
	return res
}

func (dra *dumpRequestArray) Set(value string) error {
	req, ok := map[string]upd.DumpControlRequest{
		"+d": upd.DumpControlRequest{
			EnableTrace: true,
			TraceType:   upd.TraceType_DUMP_DROP,
		},
		"-d": upd.DumpControlRequest{
			EnableTrace: false,
			TraceType:   upd.TraceType_DUMP_DROP,
		},
		"+t": upd.DumpControlRequest{
			EnableTrace: true,
			TraceType:   upd.TraceType_DUMP_TRANSLATE,
		},
		"-t": upd.DumpControlRequest{
			EnableTrace: false,
			TraceType:   upd.TraceType_DUMP_TRANSLATE,
		},
		"+k": upd.DumpControlRequest{
			EnableTrace: true,
			TraceType:   upd.TraceType_DUMP_KNI,
		},
		"-k": upd.DumpControlRequest{
			EnableTrace: false,
			TraceType:   upd.TraceType_DUMP_KNI,
		},
	}[value]

	if !ok {
		return fmt.Errorf("Bad dump control specification \"%s\"", value)
	}
	*dra = append(*dra, &req)
	return nil
}

func (acra *addresChangeRequestArray) String() string {
	res := ""
	for _, r := range *acra {
		res += r.String() + "\n"
	}
	return res
}

func (acra *addresChangeRequestArray) Set(value string) error {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return fmt.Errorf("Bad port index and subnet address specified \"%s\"", value)
	}
	index, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return err
	}

	ip, ipnet, err := net.ParseCIDR(parts[1])
	if err != nil {
		return err
	}
	if ip.To4() == nil {
		return fmt.Errorf("Only IPv4 addresses are supported yet: %s", parts[1])
	}
	ones, _ := ipnet.Mask.Size()

	*acra = append(*acra, &upd.InterfaceAddressChangeRequest{
		InterfaceId: uint32(index),
		PortSubnet: &upd.Subnet{
			Address: &upd.IPAddress{
				Address: ip.To4(),
			},
			MaskBitsNumber: uint32(ones),
		},
	})
	return nil
}

func (pfra *portForwardRequestArray) String() string {
	res := ""
	for _, r := range *pfra {
		res += r.String() + "\n"
	}
	return res
}

func (pfra *portForwardRequestArray) Set(value string) error {
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return fmt.Errorf("Bad port forwarding specification \"%s\"", value)
	}

	enable, ok := map[string]bool{
		"+": true,
		"-": false,
	}[parts[0]]
	if !ok {
		return fmt.Errorf("Bad port forwarding enable sign string \"%s\"", parts[0])
	}

	index, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return err
	}

	proto, ok := upd.Protocol_value[parts[2]]
	if !ok || proto == int32(upd.Protocol_UNKNOWN) {
		return fmt.Errorf("Bad protocol specified \"%s\"", parts[0])
	}

	sport, err := strconv.ParseUint(parts[3], 10, 16)
	if err != nil {
		return err
	}

	ip := net.ParseIP(parts[4])
	if ip == nil {
		return fmt.Errorf("Bad IP address specified \"%s\"", parts[4])
	}
	if ip.To4() == nil {
		return fmt.Errorf("Only IPv4 addresses are supported yet: %s", parts[1])
	}

	tport, err := strconv.ParseUint(parts[5], 10, 16)
	if err != nil {
		return err
	}

	*pfra = append(*pfra, &upd.PortForwardingChangeRequest{
		EnableForwarding: enable,
		InterfaceId:      uint32(index),
		Port: &upd.ForwardedPort{
			SourcePortNumber: uint32(sport),
			TargetAddress: &upd.IPAddress{
				Address: ip.To4(),
			},
			TargetPortNumber: uint32(tport),
			Protocol:         upd.Protocol(proto),
		},
	})
	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Printf(`Usage: client [-a server:port] [-d {+|-}{d|t|k}] [-s index:subnet] [-p {TCP|UDP|TCP6|UDP6}:port number:target IP address:target port]

Client sends GRPS requests to NAT server controlling packets trace dump,
ports subnet adresses and forwarded ports. Multiple requests of the same
type are allowed and are processed in the following order: all dump, all
subnet, all port forwarding requests.

`)
		flag.PrintDefaults()
	}
	address := flag.String("a", "localhost:60602", "Specifies server address")
	flag.Var(&dumpRequests, "d", `Control dump trace output in a form of +/- and letter,
e.g. +d or -t or +k:
    + and - mean to enable or disable corresponding trace,
    d means to trace dropped packets,
    t means to trace translated (normally sent) packets,
    k means to trace packets that were sent to KNI interface.`)
	flag.Var(&addresChangeRequests, "s", `Control network interface subnet in a form of index:subnet,
e.g. 1:192.168.5.1/24. Port index is DPDK port number. Subnet
is given in form of port IP address and prefix bits.`)
	flag.Var(&portForwardRequests, "p", `Control TCP and UDP port forwarding in a form of
+/-:index:protocol:source port:target IP address:target port, e.g.
+:1:TCP:2222:192.168.5.7:22 or -:0:TCP:22:0.0.0.0:0. If target
address is zero, it means that port is forwarded to corresponding
network port KNI interface. Port forwarding to a non-zero
target address (not to a KNI interface) is possible only for
public network port.`)
	flag.Parse()

	// Set up a connection to the server.
	conn, err := grpc.Dial(*address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := upd.NewUpdaterClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, r := range dumpRequests {
		reply, err := c.ControlDump(ctx, r)
		if err != nil {
			log.Fatalf("could not update: %v", err)
		}
		log.Printf("update successful: \"%s\"", reply.String())
	}

	for _, r := range addresChangeRequests {
		reply, err := c.ChangeInterfaceAddress(ctx, r)
		if err != nil {
			log.Fatalf("could not update: %v", err)
		}
		log.Printf("update successful: \"%s\"", reply.String())
	}

	for _, r := range portForwardRequests {
		reply, err := c.ChangePortForwarding(ctx, r)
		if err != nil {
			log.Fatalf("could not update: %v", err)
		}
		log.Printf("update successful: \"%s\"", reply.String())
	}
}
