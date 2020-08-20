// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package generator

import (
	"fmt"
	"math/rand"
	"os"
	"sync/atomic"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var gen generator

type generator struct {
	count uint64
}

// GetGenerator returns generator struct pointer
// generator is single and created only once
func GetGenerator() *generator {
	return &gen
}

// GetGeneratedNumber returns a number of packets generated
func (g *generator) GetGeneratedNumber() uint64 {
	return atomic.LoadUint64(&(g.count))
}

// ReadConfig function reads and parses config file.
func ReadConfig(fileName string) (GeneratorConfig, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("opening file failed with: %v ", err)
	}
	cfg, err := ParseConfigFile(f)
	if err != nil {
		return nil, fmt.Errorf("parsing config failed with: %v", err)
	}
	return cfg, nil
}

func getGenerator(configuration PacketConfig) (func(*packet.Packet, *PacketConfig, *rand.Rand), error) {
	switch configuration.DType {
	case ETHERHDR:
		l2 := configuration.Ether
		switch l2.DType {
		case IPv4HDR:
			l3 := l2.IPv4
			switch l3.DType {
			case TCPHDR:
				return generateTCPIPv4, nil
			case UDPHDR:
				return generateUDPIPv4, nil
			case ICMPHDR:
				return generateICMPIPv4, nil
			case DATA:
				return generateIPv4, nil
			default:
				return nil, fmt.Errorf("unknown packet l4 configuration")
			}
		case IPv6HDR:
			l3 := l2.IPv6
			switch l3.DType {
			case TCPHDR:
				return generateTCPIPv6, nil
			case UDPHDR:
				return generateUDPIPv6, nil
			case ICMPHDR:
				return generateICMPIPv6, nil
			case DATA:
				return generateIPv6, nil
			default:
				return nil, fmt.Errorf("unknown packet l4 configuration")
			}
		case ARPHDR:
			return generateARP, nil
		case DATA:
			return generateEther, nil
		default:
			return nil, fmt.Errorf("unknown packet l3 configuration")
		}
	case PCAP:
		pcap := configuration.Pcap
		if pcap.InMemory {
			return generatePcapInMemory, nil
		}
		return generatePcap, nil
	default:
		return nil, fmt.Errorf("unknown packet l2 configuration")
	}
}

// one unit for each mix
type generatorTableUnit struct {
	have, need    uint32
	generatorFunc func(*packet.Packet, *PacketConfig, *rand.Rand)
	config        PacketConfig
}

func (gtu *generatorTableUnit) String() string {
	return fmt.Sprintf("need: %d, config: %v\n", gtu.need, gtu.config)
}

type genParameters struct {
	table  []generatorTableUnit
	next   uint32
	length uint32
	rnd    *rand.Rand
}

func (gp genParameters) Copy() interface{} {
	ret := new(genParameters)
	ret.table = make([]generatorTableUnit, len(gp.table))
	copy(ret.table, gp.table)
	ret.length = gp.length
	ret.rnd = rand.New(rand.NewSource(13))
	return ret
}

func (gp genParameters) Delete() {
}

// GetContext gets generator context according to config
func GetContext(mixConfig GeneratorConfig) (*genParameters, error) {
	var t []generatorTableUnit
	for _, packetConfig := range mixConfig {
		genFunc, err := getGenerator(packetConfig.Config)
		if err != nil {
			return nil, err
		}
		tu := generatorTableUnit{have: 0, need: packetConfig.Quantity, generatorFunc: genFunc, config: packetConfig.Config}
		t = append(t, tu)
	}
	ret := new(genParameters)
	ret.table = t
	ret.length = uint32(len(t))
	ret.rnd = rand.New(rand.NewSource(13))
	return ret, nil
}

// Generate is a main generatior func
func Generate(pkt *packet.Packet, context flow.UserContext) {
	genP := context.(*genParameters)
	if genP.length > 1 {
		if genP.table[genP.next].have == genP.table[genP.next].need {
			genP.table[genP.next].have = 0
			if genP.next+1 < genP.length {
				genP.next++
			} else {
				genP.next = 0
			}
		}
	}
	genP.table[genP.next].generatorFunc(pkt, &genP.table[genP.next].config, genP.rnd)
	atomic.AddUint64(&(gen.count), 1)
	genP.table[genP.next].have++
}
