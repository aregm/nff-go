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

const flowN = 3

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

	l3Rules, err = packet.GetL3ACLFromORIG("rules2.conf")
	CheckFatal(err)
	go updateSeparateRules()
	firstFlow, err := flow.SetReceiver(uint8(0))
	CheckFatal(err)
	outputFlows, err := flow.SetSplitter(firstFlow, mySplitter, flowN, nil)
	CheckFatal(err)
	CheckFatal(flow.SetStopper(outputFlows[0]))
	for i := 1; i < flowN; i++ {
		CheckFatal(flow.SetHandler(outputFlows[i], modifyPacket[i-1], nil))
		CheckFatal(flow.SetSender(outputFlows[i], uint8(i-1)))
	}
	CheckFatal(flow.SystemStart())
}

func mySplitter(cur *packet.Packet, ctx flow.UserContext) uint {
	localL3Rules := l3Rules
	return cur.L3ACLPort(localL3Rules)
}

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		var err error
		l3Rules, err = packet.GetL3ACLFromORIG("rules2.conf")
		CheckFatal(err)
	}
}
