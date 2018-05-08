package main

import "sync/atomic"
import "time"
import "unsafe"
import "github.com/intel-go/nff-go/common"
import "github.com/intel-go/nff-go/flow"
import "github.com/intel-go/nff-go/packet"

var rulesp unsafe.Pointer

func main() {
	config := flow.Config{}
	flow.CheckFatal(flow.SystemInit(&config))

	initCommonState()

	l3Rules, err := packet.GetL3ACLFromORIG("rules2.conf")
	flow.CheckFatal(err)
	rulesp = unsafe.Pointer(&l3Rules)
	go updateSeparateRules()

	firstFlow, err := flow.SetReceiver(0)
	flow.CheckFatal(err)
	outputFlows, err := flow.SetSplitter(firstFlow, mySplitter, flowN, nil)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetStopper(outputFlows[0]))
	flow.CheckFatal(flow.SetHandler(outputFlows[1], myHandler, nil))
	for i := uint16(1); i < flowN; i++ {
		flow.CheckFatal(flow.SetHandler(outputFlows[i], modifyPacket[i-1], nil))
		flow.CheckFatal(flow.SetSender(outputFlows[i], i-1))
	}
	flow.CheckFatal(flow.SystemStart())
}

func mySplitter(cur *packet.Packet, ctx flow.UserContext) uint {
	localL3Rules := (*packet.L3Rules)(atomic.LoadPointer(&rulesp))
	return cur.L3ACLPort(localL3Rules)
}

func myHandler(cur *packet.Packet, ctx flow.UserContext) {
	cur.EncapsulateHead(common.EtherLen, common.IPv4MinLen)
	cur.ParseL3()
	cur.GetIPv4NoCheck().SrcAddr = packet.BytesToIPv4(111, 22, 3, 0)
	cur.GetIPv4NoCheck().DstAddr = packet.BytesToIPv4(3, 22, 111, 0)
	cur.GetIPv4NoCheck().VersionIhl = 0x45
	cur.GetIPv4NoCheck().NextProtoID = 0x04
}

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		locall3Rules, err := packet.GetL3ACLFromORIG("rules2.conf")
		flow.CheckFatal(err)
		atomic.StorePointer(&rulesp, unsafe.Pointer(locall3Rules))
	}
}
