package main

import (
	"time"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var (
	l3Rules *packet.L3Rules
)

const flowN = 3

func main() {
	config := flow.Config{}
	flow.SystemInit(&config)
	initCommonState()
	l3Rules = packet.GetL3ACLFromORIG("rules2.conf")
	go updateSeparateRules()
	firstFlow := flow.SetReceiver(0)
	outputFlows := flow.SetSplitter(firstFlow, mySplitter, flowN, nil)
	flow.SetStopper(outputFlows[0])
	flow.SetHandler(outputFlows[1], myHandler, nil)
	for i := 1; i < flowN; i++ {
		flow.SetHandler(outputFlows[i], modifyPacket[i-1], nil)
		flow.SetSender(outputFlows[i], uint8(i-1))
	}
	flow.SystemStart()
}

func mySplitter(cur *packet.Packet, ctx flow.UserContext) uint {
	localL3Rules := l3Rules
	return cur.L3ACLPort(localL3Rules)
}

func myHandler(curV []*packet.Packet, num uint, ctx flow.UserContext) {
	for i := uint(0); i < num; i++ {
		cur := curV[i]
		cur.EncapsulateHead(common.EtherLen, common.IPv4MinLen)
		cur.ParseL3()
		cur.GetIPv4().SrcAddr = packet.BytesToIPv4(111, 22, 3, 0)
		cur.GetIPv4().DstAddr = packet.BytesToIPv4(3, 22, 111, 0)
		cur.GetIPv4().VersionIhl = 0x45
		cur.GetIPv4().NextProtoID = 0x04
	}
}

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		l3Rules = packet.GetL3ACLFromORIG("rules2.conf")
	}
}
