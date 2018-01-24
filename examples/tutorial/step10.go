package main

import "sync/atomic"
import "time"
import "unsafe"
import "github.com/intel-go/yanff/common"
import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

var rulesp unsafe.Pointer

func main() {
	config := flow.Config{}
	checkFatal(flow.SystemInit(&config))

	initCommonState()

	l3Rules, err := packet.GetL3ACLFromORIG("rules2.conf")
	checkFatal(err)
	rulesp = unsafe.Pointer(&l3Rules)
	go updateSeparateRules()

	firstFlow, err := flow.SetReceiver(0)
	checkFatal(err)
	outputFlows, err := flow.SetSplitter(firstFlow, mySplitter, flowN, nil)
	checkFatal(err)
	checkFatal(flow.SetStopper(outputFlows[0]))
	checkFatal(flow.SetVectorHandler(outputFlows[1], myHandler, nil))
	for i := uint8(1); i < flowN; i++ {
		checkFatal(flow.SetHandler(outputFlows[i], modifyPacket[i-1], nil))
		checkFatal(flow.SetSender(outputFlows[i], i-1))
	}
	checkFatal(flow.SystemStart())
}

func mySplitter(cur *packet.Packet, ctx flow.UserContext) uint {
	localL3Rules := (*packet.L3Rules)(atomic.LoadPointer(&rulesp))
	return cur.L3ACLPort(localL3Rules)
}

func myHandler(curV []*packet.Packet, num uint, ctx flow.UserContext) {
	for i := uint(0); i < num; i++ {
		cur := curV[i]
		cur.EncapsulateHead(common.EtherLen, common.IPv4MinLen)
		cur.ParseL3()
		cur.GetIPv4NoCheck().SrcAddr = packet.BytesToIPv4(111, 22, 3, 0)
		cur.GetIPv4NoCheck().DstAddr = packet.BytesToIPv4(3, 22, 111, 0)
		cur.GetIPv4NoCheck().VersionIhl = 0x45
		cur.GetIPv4NoCheck().NextProtoID = 0x04
	}
}

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		locall3Rules, err := packet.GetL3ACLFromORIG("rules2.conf")
		checkFatal(err)
		atomic.StorePointer(&rulesp, unsafe.Pointer(locall3Rules))
	}
}
