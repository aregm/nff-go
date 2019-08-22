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
                tgtLoss          float64
                trafDelay        uint
                genConfig, cores string
                inPort           uint
                outPort          uint
        )
        flag.Uint64Var(&speed, "speed", 120000000, "speed of fast generator, Pkts/s")
        flag.Float64Var(&tgtLoss, "target loss", 0.5, "target packet loss percentage")
        flag.UintVar(&trafDelay, "traffic delay", 3, "time delay after speed is updated, sec")
        flag.StringVar(&genConfig, "config", "ip4.json", "specifies config for generator")
        flag.StringVar(&cores, "cores", "", "specifies cores")
        flag.UintVar(&outPort, "outPort", 1, "specifies output port")
        flag.UintVar(&inPort, "inPort", 1, "specifices input port")
        testTime := flag.Uint("t", 0, "run generator for specified period of time in seconds, use zero to run forever")
        statInterval := flag.Uint("s", 0, "statistics update interval in seconds, use zero to disable it")
        flag.Parse()


        portStats := IpPort {
                Index: uint16(inPort),
        }

        // Init NFF-GO system at 16 available cores
        config := flow.Config {
                CPUList: cores,
        }
        flow.CheckFatal(flow.SystemInit(&config))

        configuration, err := generator.ReadConfig(genConfig)
        if err != nil {
                panic(fmt.Sprintf("%s config reading failed: %v", genConfig, err))
        }
        context, err := generator.GetContext(configuration)
        flow.CheckFatal(err)
        outFlow, genChan, _ := flow.SetFastGenerator(generator.Generate, speed, context)
        flow.CheckFatal(flow.SetSender(outFlow, uint16(outPort)))

        hc := HandlerContext {
                port: &portStats,
        }
        inFlow, err := flow.SetReceiver(uint16(inPort))
        flow.CheckFatal(err)
        flow.CheckFatal(flow.SetHandlerDrop(inFlow, receiveHandler, hc))
        flow.CheckFatal(flow.SetStopper(inFlow))

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
        if *statInterval > 0 {
                statsChannel = time.NewTicker(time.Duration(*statInterval) * time.Second).C
        }

        started := time.Now()

        // optimize speed based on packet loss:
        maxSpeed := -1
        var maxSpeedPkt float64 = -1
        var totalPktRX, totalPktTX uint64 = 0, 0

        go func() {
                gen := generator.GetGenerator()
                low := 0
                high := 100
                currSpeed := 100

                // data at line rate:
                portStats.packetCount = 0
                gen.Count = 0
                time.Sleep(time.Duration(trafDelay) * time.Second)
                pktRX := portStats.packetCount
                pktTX := gen.GetGeneratedNumber()
                pktLoss := calcPktLoss(pktRX, pktTX)
                totalPktRX += pktRX
                totalPktTX += pktTX
                printStats(&portStats, pktRX, pktTX, pktLoss, started, currSpeed, float64(speed))

                // binary search:
                for low <= high {
                        mid := (low + high) / 2
                        currSpeed = mid
                        updatedSpeed := 0.01 * float64(uint64(currSpeed) * speed)

                        // reset counters:
                        portStats.packetCount = 0
                        gen.Count = 0

                        genChan <- uint64(updatedSpeed)
                        time.Sleep(time.Duration(trafDelay) * time.Second)

                        pktRX = portStats.packetCount
                        pktTX = gen.GetGeneratedNumber()
                        pktLoss = calcPktLoss(pktRX, pktTX)

                        if pktLoss <= tgtLoss {
                                low = mid + 1 // tgt met so try higher speed
                                if currSpeed > maxSpeed {
                                        maxSpeed = currSpeed
                                        maxSpeedPkt = updatedSpeed
                                }
                        } else {
                                high = mid - 1 // tgt failed so try lower speed
                        }

                        totalPktRX += pktRX
                        totalPktTX += pktTX
                        // fmt.Printf("\nmid: %d\nupdatedSpeed: %d%%(%f pkt/s)\npktCountTX: %d\npktCountRX: %d\npktLoss: %f\nlow: %d\nhigh: %d\n\n", mid, currSpeed, updatedSpeed, pktTX, pktRX, pktLoss, low, high) // debugging purposes

                        printStats(&portStats, pktRX, pktTX, pktLoss, started, currSpeed, updatedSpeed)
                }
                fmt.Printf("--------------------BINARY SEARCH COMPLETE!!!--------------------\n")
                interruptChannel <- os.Interrupt
        }()


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
                        printStats(&portStats, totalPktRX, totalPktTX, calcPktLoss(totalPktRX, totalPktTX), started, maxSpeed, maxSpeedPkt)
                }
        }
        printTotals(&portStats, totalPktRX, totalPktTX, started, maxSpeed, maxSpeedPkt)
}

func calcPktLoss(pktCountRX uint64, pktCountTX uint64) float64 {
        return (float64(pktCountTX - pktCountRX) / float64(pktCountTX)) * 100.0
}

func receiveHandler(pkt *packet.Packet, ctx flow.UserContext) bool {
        hc := ctx.(HandlerContext)

        atomic.AddUint64(&hc.port.packetCount, 1)
        atomic.AddUint64(&hc.port.bytesCount, uint64(pkt.GetPacketLen()))
        return true
}

func printStats(port *IpPort, pktRX uint64, pktTX uint64, pktLoss float64, started time.Time, currSpeed int, updatedSpeed float64) {
        fmt.Printf("\n%v: ", time.Since(started))
        fmt.Printf("Port %d pkts TX: %d / pkts RX: %d\n", port.Index, pktTX, pktRX)
        fmt.Printf("Pkt loss: %f%%\n", pktLoss)
        fmt.Printf("Current Speed: %d%% (%f pkts/s)\n\n", currSpeed, updatedSpeed)
}

func printTotals(port *IpPort, totalPktRX uint64, totalPktTX uint64, started time.Time, maxSpeed int, maxSpeedPkt float64) {
        runtime := time.Since(started)
        runtimeint := uint64(runtime) / uint64(time.Second)
        totalPktLoss := calcPktLoss(totalPktRX, totalPktTX)
        fmt.Printf("\nTest executed for %v\n", runtime)
        fmt.Printf("Port %d total pkts TX: %d / pkts RX: %d\n", port.Index, totalPktTX, totalPktRX)
        fmt.Printf("Total pkt loss: %f%%\n", totalPktLoss)
        fmt.Printf("Port %d pkts/s: %v\n", port.Index, totalPktRX/runtimeint)
        fmt.Printf("Port %d kB/s: %v\n", port.Index, port.bytesCount/runtimeint/1000)
        fmt.Printf("Max Speed: %d%% (%f pkts/s)\n\n", maxSpeed, maxSpeedPkt)
}
