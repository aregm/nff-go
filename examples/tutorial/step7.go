package main

import (
	"fmt"
	"os"
	"time"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var (
	l3Rules *packet.L3Rules
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfail: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	var err error
	config := flow.Config{}
	CheckFatal(flow.SystemInit(&config))

	initCommonState()

	l3Rules, err = packet.GetL3ACLFromORIG("rules1.conf")
	CheckFatal(err)

	go updateSeparateRules()
	firstFlow, err := flow.SetReceiver(uint8(0))
	CheckFatal(err)
	secondFlow, err := flow.SetSeparator(firstFlow, mySeparator, nil)
	CheckFatal(err)
	CheckFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	CheckFatal(flow.SetHandler(secondFlow, modifyPacket[1], nil))
	CheckFatal(flow.SetSender(firstFlow, uint8(0)))
	CheckFatal(flow.SetStopper(secondFlow))
	CheckFatal(flow.SystemStart())
}

func mySeparator(cur *packet.Packet, ctx flow.UserContext) bool {
	localL3Rules := l3Rules
	return cur.L3ACLPermit(localL3Rules)
}

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		var err error
		l3Rules, err = packet.GetL3ACLFromORIG("rules1.conf")
		CheckFatal(err)
	}
}
