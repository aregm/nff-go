package main

import (
	"time"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"github.com/intel-go/yanff/rules"
)

var (
	l3Rules *rules.L3Rules
)

const flowN = 3

func main() {
	config := flow.Config{}
	flow.SystemInit(&config)
	initCommonState()
	l3Rules = rules.GetL3RulesFromORIG("rules2.conf")
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
	return rules.L3ACLPort(cur, localL3Rules)
}

func myHandler(curV []*packet.Packet, num uint, ctx flow.UserContext) {
	for i := uint(0); i < num; i++ {
		cur := curV[i]
		cur.EncapsulateHead(common.EtherLen, common.IPv4MinLen)
		cur.ParseL3()
		cur.GetIPv4().SrcAddr = packet.IPv4(111, 22, 3, 0)
		cur.GetIPv4().DstAddr = packet.IPv4(3, 22, 111, 0)
		cur.GetIPv4().VersionIhl = 0x45
		cur.GetIPv4().NextProtoID = 0x04
	}
	// Some heavy computational code
	heavyCode()
}

func heavyCode() {
	for i := 0; i < 1000000; i++ {
	}
}

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		l3Rules = rules.GetL3RulesFromORIG("rules2.conf")
	}
}
