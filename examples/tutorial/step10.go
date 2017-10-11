package main

import "time"
import "github.com/intel-go/yanff/common"
import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"
import "github.com/intel-go/yanff/rules"

var (
	L3Rules *rules.L3Rules
)

const flowN = 3

func main() {
	config := flow.Config{}
	flow.SystemInit(&config)
	initCommonState()
	L3Rules = rules.GetL3RulesFromORIG("rules2.conf")
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
	localL3Rules := L3Rules
	return rules.L3ACLPort(cur, localL3Rules)
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
	for true {
		time.Sleep(time.Second * 5)
		L3Rules = rules.GetL3RulesFromORIG("rules2.conf")
	}
}
