package main

import "sync/atomic"
import "time"
import "unsafe"
import "github.com/intel-go/nff-go/flow"
import "github.com/intel-go/nff-go/packet"

var rulesp unsafe.Pointer

func main() {
	config := flow.Config{}
	flow.CheckFatal(flow.SystemInit(&config))

	initCommonState()

	l3Rules, err := packet.GetL3ACLFromORIG("rules1.conf")
	flow.CheckFatal(err)
	rulesp = unsafe.Pointer(&l3Rules)
	go updateSeparateRules()

	firstFlow, err := flow.SetReceiver(0)
	flow.CheckFatal(err)
	secondFlow, err := flow.SetSeparator(firstFlow, mySeparator, nil)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	flow.CheckFatal(flow.SetHandler(secondFlow, modifyPacket[1], nil))
	flow.CheckFatal(flow.SetSender(firstFlow, 0))
	flow.CheckFatal(flow.SetStopper(secondFlow))
	flow.CheckFatal(flow.SystemStart())
}

func mySeparator(cur *packet.Packet, ctx flow.UserContext) bool {
	localL3Rules := (*packet.L3Rules)(atomic.LoadPointer(&rulesp))
	return cur.L3ACLPermit(localL3Rules)
}

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		locall3Rules, err := packet.GetL3ACLFromORIG("rules1.conf")
		flow.CheckFatal(err)
		atomic.StorePointer(&rulesp, unsafe.Pointer(locall3Rules))
	}
}
