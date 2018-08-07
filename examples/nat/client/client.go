package main

import (
	"log"
	"time"

	upd "github.com/intel-go/nff-go/examples/nat/updatecfg"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	address = "localhost:60602"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := upd.NewUpdaterClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Private
	r, err := c.UpdateNATConfigPrivateSubnet(ctx, &upd.UpdatePrivateRequest{Upd: &upd.UpdatePrivate{PrivatePort: 0, PublicPort: 1, PrivateSubnet: "192.168.14.1/24", PortFwdDst: "192.168.14.2/32"}})
	if err != nil {
		log.Fatalf("could not update: %v", err)
	}
	log.Printf("update successful: %s", r.Message)

	// Public
	r, err = c.UpdateNATConfigPublicSubnet(ctx, &upd.UpdatePublicRequest{Upd: &upd.UpdatePublic{PrivatePort: 0, PublicPort: 1, PublicSubnet: "192.168.16.1/24"}})
	if err != nil {
		log.Fatalf("could not update: %v", err)
	}
	log.Printf("update successful: %s", r.Message)

}
