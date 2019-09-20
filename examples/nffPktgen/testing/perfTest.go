// Copyright 2018-2019 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/examples/nffPktgen/generator"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

type IpPort struct {
	Index       uint16
	packetCount uint64
	bytesCount  uint64
}

type HandlerContext struct {
	port *IpPort
}

func (hc HandlerContext) Copy() interface{} {
	return HandlerContext{
		port: hc.port,
	}
}

func (hc HandlerContext) Delete() {
}

func main() {
	var (
		speed            uint64
		genConfig, cores string
		port             uint
		receive          bool
	)
	flag.Uint64Var(&speed, "speed", 120000000, "speed of fast generator, Pkts/s")
	flag.StringVar(&genConfig, "config", "ip4.json", "specifies config for generator")
	flag.StringVar(&cores, "cores", "0-2", "specifies cores")
	flag.UintVar(&port, "port", 1, "specifies output port")
	flag.BoolVar(&receive, "receive", false, "Receive packets back and print statistics")
	testTime := flag.Uint("t", 30, "run generator for specified period of time in seconds, use zero to run forever")
	statInterval := flag.Uint("s", 2, "statistics update interval in seconds, use zero to disable it")
	flag.Parse()

	portStats := IpPort{
		Index: uint16(port),
	}

	// Init NFF-GO system at 16 available cores
	config := flow.Config{
		CPUList: cores,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	configuration, err := generator.ReadConfig(genConfig)
	if err != nil {
		panic(fmt.Sprintf("%s config reading failed: %v", genConfig, err))
	}
	context, err := generator.GetContext(configuration)
	flow.CheckFatal(err)
	outFlow, _, _ := flow.SetFastGenerator(generator.Generate, speed, context)
	flow.CheckFatal(flow.SetSender(outFlow, uint16(port)))
	if receive {
		hc := HandlerContext{
			port: &portStats,
		}
		inFlow, err := flow.SetReceiver(uint16(port))
		flow.CheckFatal(err)
		flow.CheckFatal(flow.SetHandlerDrop(inFlow, receiveHandler, hc))
		flow.CheckFatal(flow.SetStopper(inFlow))
	}

	go func() {
		flow.CheckFatal(flow.SystemStart())
	}()

	// Set up finish channels
	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, os.Interrupt)

	var finishChannel, statsChannel <-chan time.Time
	if *testTime > 0 {
		finishChannel = time.NewTicker(time.Duration(*testTime) * time.Second).C
	}
	if receive && *statInterval > 0 {
		statsChannel = time.NewTicker(time.Duration(*statInterval) * time.Second).C
	}

	started := time.Now()
out:
	for {
		select {
		case sig := <-interruptChannel:
			fmt.Printf("Received signal %v, finishing.\n", sig)
			break out
		case <-finishChannel:
			fmt.Println("Test timeout reached")
			break out
		case <-statsChannel:
			printStats(&portStats, started)
		}
	}
	if receive {
		printStats(&portStats, started)
		printTotals(&portStats, started)
	}
}

func receiveHandler(pkt *packet.Packet, ctx flow.UserContext) bool {
	hc := ctx.(HandlerContext)

	atomic.AddUint64(&hc.port.packetCount, 1)
	atomic.AddUint64(&hc.port.bytesCount, uint64(pkt.GetPacketLen()))
	return true
}

func printStats(port *IpPort, started time.Time) {
	fmt.Printf("%v: ", time.Since(started))
	fmt.Printf("Port %d received %vpkts, %vkB\n", port.Index, port.packetCount, port.bytesCount/1000)
}

func printTotals(port *IpPort, started time.Time) {
	runtime := time.Since(started)
	runtimeint := uint64(runtime) / uint64(time.Second)
	fmt.Printf("\nTest executed for %v\n", runtime)
	fmt.Printf("Port %d pkts/s: %v\n", port.Index, port.packetCount/runtimeint)
	fmt.Printf("Port %d kB/s: %v\n", port.Index, port.bytesCount/runtimeint/1000)
}
