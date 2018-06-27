package main

import "sync/atomic"
import "time"
import "unsafe"
import "github.com/intel-go/nff-go/flow"
import "github.com/intel-go/nff-go/packet"

var rulesp unsafe.Pointer

func main() {
	flow.CheckFatal(flow.SystemInit(nil))

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

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		locall3Rules, err := packet.GetL3ACLFromORIG("rules2.conf")
		flow.CheckFatal(err)
		atomic.StorePointer(&rulesp, unsafe.Pointer(locall3Rules))
	}
}
