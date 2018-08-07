package main

import (
	"log"
	"time"

	upd "github.com/intel-go/nff-go/examples/nat/updatecfg"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	address     = "localhost:60602"
	defaultName = "world"
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
	r, err := c.UpdateNATConfig(ctx, &upd.UpdateRequest{Upd: &upd.Update{PrivateSubnet: "192.168.14.1/24", PublicSubnet: "192.168.16.1/32", PublicDstMac: "3C:FD:FE:A4:DD:F0"}})
	if err != nil {
		log.Fatalf("could not update: %v", err)
	}
	log.Printf("update successful: %s", r.Message)
}
