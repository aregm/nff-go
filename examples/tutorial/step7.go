package main

import "sync/atomic"
import "time"
import "unsafe"
import "github.com/intel-go/yanff/flow"
import "github.com/intel-go/yanff/packet"

var rulesp unsafe.Pointer

func main() {
	config := flow.Config{}
	checkFatal(flow.SystemInit(&config))

	initCommonState()

	l3Rules, err := packet.GetL3ACLFromORIG("rules1.conf")
	checkFatal(err)
	rulesp = unsafe.Pointer(&l3Rules)
	go updateSeparateRules()

	firstFlow, err := flow.SetReceiver(0)
	checkFatal(err)
	secondFlow, err := flow.SetSeparator(firstFlow, mySeparator, nil)
	checkFatal(err)
	checkFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	checkFatal(flow.SetHandler(secondFlow, modifyPacket[1], nil))
	checkFatal(flow.SetSender(firstFlow, 0))
	checkFatal(flow.SetStopper(secondFlow))
	checkFatal(flow.SystemStart())
}

func mySeparator(cur *packet.Packet, ctx flow.UserContext) bool {
	localL3Rules := (*packet.L3Rules)(atomic.LoadPointer(&rulesp))
	return cur.L3ACLPermit(localL3Rules)
}

func updateSeparateRules() {
	for {
		time.Sleep(time.Second * 5)
		locall3Rules, err := packet.GetL3ACLFromORIG("rules1.conf")
		checkFatal(err)
		atomic.StorePointer(&rulesp, unsafe.Pointer(locall3Rules))
	}
}
