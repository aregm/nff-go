// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var received uint64

type ctx struct {
	received uint64
}

var ccc []*uint64

func (c ctx) Copy() interface{} {
	n := new(ctx)
	ccc = append(ccc, &(n.received))
	return n
}

func (c ctx) Delete() {
}

func main() {
	inport := flag.Uint("inport", 0, "port for receiver")
	s := flag.Uint("size", 64, "size of packets")
	flag.Parse()

	config := flow.Config{
		StopOnDedicatedCore: true,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	firstFlow, err := flow.SetReceiver(uint16(*inport))
	flow.CheckFatal(err)

	go report(uint64(*s))

	flow.CheckFatal(flow.SetVectorHandler(firstFlow, count, *new(ctx)))
	flow.CheckFatal(flow.SetStopper(firstFlow))

	flow.CheckFatal(flow.SystemStart())
}

func count(currentPacket []*packet.Packet, mask *[32]bool, context flow.UserContext) {
	var i uint64
	for i = 0; i < 32; i++ {
		if mask[i] == false {
			break
		}
	}
	ctx1 := context.(*ctx)
	atomic.AddUint64(&(ctx1.received), i)
}

func report(size uint64) {
	for {
		time.Sleep(time.Second)
		var number uint64
		for i := 0; i < len(ccc); i++ {
			number += atomic.LoadUint64(ccc[i])
			atomic.StoreUint64(ccc[i], 0)
		}
		fmt.Println("Output: Packets/sec:", number, "Mbits/sec:", number*8*(size+20)/1000/1000)
	}
}
