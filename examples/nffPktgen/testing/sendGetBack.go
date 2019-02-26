// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intel-go/nff-go/examples/nffPktgen/generator"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var (
	number, numberGot, recv uint64
	isCycled                bool
	testDoneEvent           *sync.Cond
)

type mapFlags struct {
	value map[interface{}]string
	set   bool
}

func parseStr(s string) string {
	indx := strings.Index(s, "'")
	substr := s[indx+1:]
	indx = strings.Index(substr, "'")
	return substr[:indx]
}

func parseIntOrStr(s string) interface{} {
	var parsed interface{}
	var err error
	parsed, err = strconv.Atoi(s)
	if err != nil {
		parsed = parseStr(s)
	}
	return parsed
}

func (m *mapFlags) String() string {
	s := ""
	for key, value := range (*m).value {
		if s != "" {
			s += ","
		}
		if k, ok := key.(int); ok {
			s += fmt.Sprintf("%d: '%s'", k, value)
		} else {
			s += fmt.Sprintf("'%v': '%s'", key, value)
		}
	}
	return s
}

func (m *mapFlags) Set(s string) error {
	ss := strings.Split(s, ",")
	(*m).value = make(map[interface{}]string)
	for _, val := range ss {
		val = strings.TrimSpace(val)
		pair := strings.Split(val, ":")
		value := parseStr(pair[1])
		(*m).value[parseIntOrStr(pair[0])] = value
	}
	(*m).set = true
	return nil
}

type listFlags struct {
	value []interface{}
	set   bool
}

func (l *listFlags) String() string {
	s := ""
	for _, value := range (*l).value {
		if s != "" {
			s += ", "
		}
		if v, ok := value.(int); ok {
			s += fmt.Sprintf("%d", v)
		} else {
			s += fmt.Sprintf("'%s'", value)
		}
	}
	return s
}

func (l *listFlags) Set(s string) error {
	ss := strings.Split(s, ",")
	for _, val := range ss {
		val = strings.TrimSpace(val)
		(*l).value = append((*l).value, parseIntOrStr(val))
	}
	(*l).set = true
	return nil
}

func main() {
	var (
		speed             uint64
		m                 sync.Mutex
		eachOutPortConfig mapFlags
		eachInPortConfig  listFlags
	)
	flag.Uint64Var(&number, "number", 0, "stop after generated number")
	flag.Uint64Var(&numberGot, "numberGot", 10000000, "stop after got number")
	flag.BoolVar(&isCycled, "cycle", false, "cycle execution")
	flag.Uint64Var(&speed, "speed", 6000000, "speed of fast generator, Pkts/s")
	flag.Var(&eachOutPortConfig, "outConfig", "specifies config per port portNum or file: 'path', 'pcapOut': 'path2'. For example: 1: 'ip4.json', 'mix.pcap': 'mix.json'")
	flag.Var(&eachInPortConfig, "inConfig", "specifies input ports and files 'path', portNum2, 'path2'. For example: 1, 'ip4.pcap', 0, 'mix.pcap'")
	flag.Parse()

	// Init NFF-GO system at 16 available cores
	config := flow.Config{
		CPUList:          "0-43",
		DisableScheduler: true,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	testDoneEvent = sync.NewCond(&m)
	if !eachOutPortConfig.set {
		eachOutPortConfig.Set("0: '../testing/config.json'")
	}
	for key, value := range eachOutPortConfig.value {
		configuration, err := generator.ReadConfig(value)
		if err != nil {
			panic(fmt.Sprintf("%s config reading failed: %v", value, err))
		}
		context, err := generator.GetContext(configuration)
		flow.CheckFatal(err)
		outFlow, _, err := flow.SetFastGenerator(generator.Generate, speed, context)
		flow.CheckFatal(err)
		switch t := key.(type) {
		case int:
			flow.CheckFatal(flow.SetSender(outFlow, uint16(t)))
		case string:
			flow.CheckFatal(flow.SetSenderFile(outFlow, t))
		default:
			panic(fmt.Sprintf("Unrecognized type in outConfig: %v", key))
		}
	}
	for _, value := range eachInPortConfig.value {
		var (
			inFlow *flow.Flow
			err    error
		)
		switch t := value.(type) {
		case int:
			inFlow, err = flow.SetReceiver(uint16(t))
			flow.CheckFatal(err)
		case string:
			inFlow = flow.SetReceiverFile(t, -1)
		default:
			panic(fmt.Sprintf("Unrecognized type in inConfig: %v", value))
		}
		flow.CheckFatal(flow.SetHandler(inFlow, handleRecv, nil))
		flow.CheckFatal(flow.SetStopper(inFlow))
	}

	// Start pipeline
	go func() {
		flow.CheckFatal(flow.SystemStart())
	}()

	g := generator.GetGenerator()
	go func() {
		for {
			if g.GetGeneratedNumber() >= number {
				testDoneEvent.Signal()
			}
			println("Sent/Got", g.GetGeneratedNumber(), "/", atomic.LoadUint64(&recv), "packets")
			time.Sleep(time.Second)
		}
	}()

	// Wait for enough packets to arrive
	testDoneEvent.L.Lock()
	testDoneEvent.Wait()
	testDoneEvent.L.Unlock()
	println("Sent/Got", g.GetGeneratedNumber(), "/", atomic.LoadUint64(&recv), "packets")
}

func handleRecv(currentPacket *packet.Packet, context flow.UserContext) {
	got := atomic.AddUint64(&recv, 1)
	if isCycled {
		return
	}
	if got >= numberGot {
		time.Sleep(time.Second)
		testDoneEvent.Signal()
	}
}
